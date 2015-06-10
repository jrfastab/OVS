/*
 * Copyright (c) 2015 Intel Corp.
 * Author John Fastabend
 * Note: derived from netdev-linux.c
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/gen_stats.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/types.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_packet.h>
#include <net/route.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "coverage.h"
#include "dp-packet.h"
#include "dpif-netlink.h"
#include "dpif-netdev.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "hash.h"
#include "hmap.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink-notifier.h"
#include "netlink-socket.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "poll-loop.h"
#include "rtnetlink-link.h"
#include "shash.h"
#include "socket-util.h"
#include "sset.h"
#include "timer.h"
#include "unaligned.h"
#include "openvswitch/vlog.h"

#include "if_match.h"
#include "matchlib_nl.h"
#include "models/ies_pipeline.h"
#include "fm_sdk.h"
#include "netdev-dpdk.h"

VLOG_DEFINE_THIS_MODULE(netdev_vf);

/* clumsy hack for the moment because we leak into netdev-dpdk
 * to handle receive side and set the lport value
 */
int vf_odp_port;
#define FLOW_FI_FAMILY 555
#define FM_MAIN_SWITCH 0 /* is this a safe pattern? */


static const struct netdev_class netdev_vf_class;

enum {
    VALID_IFINDEX           = 1 << 0,
    VALID_ETHERADDR         = 1 << 1,
    VALID_IN4               = 1 << 2,
    VALID_IN6               = 1 << 3,
    VALID_MTU               = 1 << 4,
    VALID_POLICING          = 1 << 5,
    VALID_VPORT_STAT_ERROR  = 1 << 6,
    VALID_DRVINFO           = 1 << 7,
    VALID_FEATURES          = 1 << 8,
};

struct netdev_vf_hw {
    struct nl_sock *nsd;
    uint32_t pid;
    int family;
    int sw;
    int vf;
    uint32_t vf_lport;
    int pf;
    int pf_lport;
};

struct netdev_vf {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    unsigned int cache_valid;

    /* The following are figured out "on demand" only.  They are only valid
     * when the corresponding VALID_* bit in 'cache_valid' is set. */
    int ifindex;
    uint8_t etheraddr[ETH_ADDR_LEN];
    int mtu;
    unsigned int ifi_flags;
    long long int carrier_resets;

    int ether_addr_error;
    int get_features_error;

    enum netdev_features current;    /* Cached from ETHTOOL_GSET. */
    enum netdev_features advertised; /* Cached from ETHTOOL_GSET. */
    enum netdev_features supported;  /* Cached from ETHTOOL_GSET. */

    struct netdev_tunnel_config tnl;

    struct netdev_vf_hw hw;
    struct netdev *root;
};

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static struct netdev_vf *
netdev_vf_cast(const struct netdev *netdev)
{
    return CONTAINER_OF(netdev, struct netdev_vf, up);
}

uint32_t
netdev_vf_lport(struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    return netdev->hw.vf_lport;
}


static void
netdev_vf_run(void)
{

}

static void
netdev_vf_wait(void)
{
}

static void
netdev_vf_changed(struct netdev_vf *dev,
                     unsigned int ifi_flags, unsigned int mask)
{
}

/* Life cycle routines */
static struct netdev *
netdev_vf_alloc(void)
{
    struct netdev_vf *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static int
netdev_vf_construct(struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    VLOG_WARN("%s: vf construct: \n", __func__); 
    ovs_mutex_init(&netdev->mutex);
    return 0;
}

static void
netdev_vf_destruct(struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    netdev_close(netdev->root);
    ovs_mutex_destroy(&netdev->mutex);
}

static void
netdev_vf_dealloc(struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    free(netdev);
}

/* Sends 'buffer' on 'netdev'.  Returns 0 if successful, otherwise a positive
 * errno value.  Returns EAGAIN without blocking if the packet cannot be queued
 * immediately.  Returns EMSGSIZE if a partial packet was transmitted or if
 * the packet is too big or too small to transmit on the device.
 *
 * This routine is pretty simple and unoptimized basic support just to get this
 * working. Might be better to use the DPDK routines at some point.
 *
 * The caller retains ownership of 'buffer' in all cases. */
static int
netdev_vf_send(struct netdev *netdev_, int qid OVS_UNUSED,
                  struct dp_packet **pkts, int cnt, bool may_steal)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    if (!netdev->root)
		return 0;

    /* This is going to break if we hit an entry in the pipeline, TBD
     * add support for direct send command
     */
    return netdev_dpdk_eth_send(netdev->root, qid, pkts, cnt, may_steal);
}

/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send(). */
static void
netdev_vf_send_wait(struct netdev *netdev, int qid OVS_UNUSED)
{
}

static int
set_etheraddr(const char *netdev_name,
              const uint8_t mac[ETH_ADDR_LEN])
{
    struct ifreq ifr;
    int error = 0;

    VLOG_ERR("TBD implement set_etherdev on %s", netdev_name);

    return error;
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
static int
netdev_vf_set_etheraddr(struct netdev *netdev_,
                           const uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    enum netdev_flags old_flags = 0;
    int error;

    ovs_mutex_lock(&netdev->mutex);

    if (netdev->cache_valid & VALID_ETHERADDR) {
        error = netdev->ether_addr_error;
        if (error || eth_addr_equals(netdev->etheraddr, mac)) {
            goto exit;
        }
        netdev->cache_valid &= ~VALID_ETHERADDR;
    }

    error = set_etheraddr(netdev_get_name(netdev_), mac);
    if (!error || error == ENODEV) {
        netdev->ether_addr_error = error;
        netdev->cache_valid |= VALID_ETHERADDR;
        if (!error) {
            memcpy(netdev->etheraddr, mac, ETH_ADDR_LEN);
        }
    }

exit:
    ovs_mutex_unlock(&netdev->mutex);
    return error;
}

static int
get_etheraddr(const char *netdev_name, uint8_t ea[ETH_ADDR_LEN])
{
    return 0;
}

/* Copies 'netdev''s MAC address to 'mac' which is passed as param. */
static int
netdev_vf_get_etheraddr(const struct netdev *netdev_,
                           uint8_t mac[ETH_ADDR_LEN])
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    if (!(netdev->cache_valid & VALID_ETHERADDR)) {
        netdev->ether_addr_error = get_etheraddr(netdev_get_name(netdev_),
                                                 netdev->etheraddr);
        netdev->cache_valid |= VALID_ETHERADDR;
    }

    error = netdev->ether_addr_error;
    if (!error) {
        memcpy(mac, netdev->etheraddr, ETH_ADDR_LEN);
    }
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_vf_get_mtu__(struct netdev_vf *netdev, int *mtup)
{
    return 0;
}

/* Returns the maximum size of transmitted (and received) packets on 'netdev',
 * in bytes, not including the hardware header; thus, this is typically 1500
 * bytes for Ethernet devices. */
static int
netdev_vf_get_mtu(const struct netdev *netdev_, int *mtup)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    error = netdev_vf_get_mtu__(netdev, mtup);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/* Sets the maximum size of transmitted (MTU) for given device using linux
 * networking ioctl interface.
 */
static int
netdev_vf_set_mtu(const struct netdev *netdev_, int mtu)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    // TBD set MTU
    ovs_mutex_unlock(&netdev->mutex);
    return 0;
}

/* Returns the ifindex of 'netdev', if successful, as a positive number.
 * On failure, returns a negative errno value. */
static int
netdev_vf_get_ifindex(const struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    int ifindex = 0;
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    ovs_mutex_unlock(&netdev->mutex);

    return error ? -error : ifindex;
}

static int
netdev_vf_get_carrier(const struct netdev *netdev_, bool *carrier)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *carrier = (netdev->ifi_flags & IFF_RUNNING) != 0;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static long long int
netdev_vf_get_carrier_resets(const struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    long long int carrier_resets;

    ovs_mutex_lock(&netdev->mutex);
    carrier_resets = netdev->carrier_resets;
    ovs_mutex_unlock(&netdev->mutex);

    return carrier_resets;
}

/* Retrieves current device stats for 'netdev-linux'. */
static int
netdev_vf_get_stats(const struct netdev *netdev_,
                       struct netdev_stats *stats)
{
#if 0
        stats->rx_packets = dev_stats.rx_packets;
        stats->rx_bytes = dev_stats.rx_bytes;
        stats->tx_packets = dev_stats.tx_packets;
        stats->tx_bytes = dev_stats.tx_bytes;

        stats->rx_errors           += dev_stats.rx_errors;
        stats->tx_errors           += dev_stats.tx_errors;
        stats->rx_dropped          += dev_stats.rx_dropped;
        stats->tx_dropped          += dev_stats.tx_dropped;
        stats->multicast           += dev_stats.multicast;
        stats->collisions          += dev_stats.collisions;
        stats->rx_length_errors    += dev_stats.rx_length_errors;
        stats->rx_over_errors      += dev_stats.rx_over_errors;
        stats->rx_crc_errors       += dev_stats.rx_crc_errors;
        stats->rx_frame_errors     += dev_stats.rx_frame_errors;
        stats->rx_fifo_errors      += dev_stats.rx_fifo_errors;
        stats->rx_missed_errors    += dev_stats.rx_missed_errors;
        stats->tx_aborted_errors   += dev_stats.tx_aborted_errors;
        stats->tx_carrier_errors   += dev_stats.tx_carrier_errors;
        stats->tx_fifo_errors      += dev_stats.tx_fifo_errors;
        stats->tx_heartbeat_errors += dev_stats.tx_heartbeat_errors;
        stats->tx_window_errors    += dev_stats.tx_window_errors;
    }
#endif
    return 0;
}

static void
netdev_vf_read_features(struct netdev_vf *netdev)
{
    netdev->supported = NETDEV_F_10GB_FD;
    netdev->supported |= NETDEV_F_FIBER;

    netdev->advertised = NETDEV_F_FIBER;
    netdev->advertised |= NETDEV_F_10GB_FD;

    netdev->current = NETDEV_F_10GB_FD;
    netdev->current |= NETDEV_F_FIBER;
}

/* Stores the features supported by 'netdev' into of '*current', '*advertised',
 * '*supported', and '*peer'.  Each value is a bitmap of NETDEV_* bits.
 * Returns 0 if successful, otherwise a positive errno value. */
static int
netdev_vf_get_features(const struct netdev *netdev_,
                          enum netdev_features *current,
                          enum netdev_features *advertised,
                          enum netdev_features *supported,
                          enum netdev_features *peer)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    int error;

    ovs_mutex_lock(&netdev->mutex);
    netdev_vf_read_features(netdev);
    if (!netdev->get_features_error) {
        *current = netdev->current;
        *advertised = netdev->advertised;
        *supported = netdev->supported;
        *peer = 0;              /* XXX */
    }
    error = netdev->get_features_error;
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

/* Set the features advertised by 'netdev' to 'advertise'. */
static int
netdev_vf_set_advertisements(struct netdev *netdev_,
                                enum netdev_features advertise)
{
    return EOPNOTSUPP;
}

/* Attempts to set input rate limiting (policing) policy.  Returns 0 if
 * successful, otherwise a positive errno value. */
static int
netdev_vf_set_policing(struct netdev *netdev_,
                          uint32_t kbits_rate, uint32_t kbits_burst)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_get_qos_types(const struct netdev *netdev OVS_UNUSED,
                           struct sset *types)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_get_qos_capabilities(const struct netdev *netdev OVS_UNUSED,
                                  const char *type,
                                  struct netdev_qos_capabilities *caps)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_get_qos(const struct netdev *netdev_,
                     const char **typep, struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_set_qos(struct netdev *netdev_,
                     const char *type, const struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_get_queue(const struct netdev *netdev_,
                       unsigned int queue_id, struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_set_queue(struct netdev *netdev_,
                       unsigned int queue_id, const struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_delete_queue(struct netdev *netdev_, unsigned int queue_id)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_get_queue_stats(const struct netdev *netdev_,
                             unsigned int queue_id,
                             struct netdev_queue_stats *stats)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_queue_dump_start(const struct netdev *netdev_, void **statep)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_queue_dump_next(const struct netdev *netdev_, void *state_,
                             unsigned int *queue_idp, struct smap *details)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_queue_dump_done(const struct netdev *netdev OVS_UNUSED,
                             void *state_)
{
    return 0;
}

static int
netdev_vf_dump_queue_stats(const struct netdev *netdev_,
                              netdev_dump_queue_stats_cb *cb, void *aux)
{
    return EOPNOTSUPP;
}

static int
netdev_vf_get_status(const struct netdev *netdev_, struct smap *smap)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_vf_update_flags(struct netdev *netdev_, enum netdev_flags off,
                          enum netdev_flags on, enum netdev_flags *old_flagsp)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);
    int error = 0;

    ovs_mutex_lock(&netdev->mutex);
    ovs_mutex_unlock(&netdev->mutex);

    return error;
}

static int
netdev_vf_get_config(const struct netdev *dev_, struct smap *args)
{
    struct netdev_vf *dev = netdev_vf_cast(dev_);

    VLOG_WARN("%s: get vf config: \n", __func__); 
    return 0;
}

/* duplicated in dpif-netdev.c*/
static uint32_t
netdev_vf_hw_pid_lookup(void)
{
    FILE *fd = fopen(MATCHLIB_PID_FILE, "r");	
    uint32_t pid;

    if (!fd) {
        VLOG_WARN("no hardware support 'daemon is not listening'");
        return 0;
    }

    fscanf(fd, "%" SCNu32 "", &pid);
    VLOG_WARN("Found pid %lu\n", pid);
    return pid;
}

fm_semaphore seqSem;

static void eventHandler(fm_int event, fm_int sw, void *ptr)
{
	fm_eventPort *portEvent = (fm_eventPort *) ptr;

	FM_NOT_USED(sw);

	switch (event) {
	case FM_EVENT_SWITCH_INSERTED:
		printf("Switch #%d inserted!\n", sw);
		if (sw == FM_MAIN_SWITCH)
			fmSignalSemaphore(&seqSem);
		break;

	case FM_EVENT_PORT:
		printf("port event: port %d is %s\n", portEvent->port, (portEvent->linkStatus ? "up" : "down"));
		break;

	case FM_EVENT_PKT_RECV:
		printf("packet received\n");
		break;
	}
}

static void
dp_netdev_flow_mac_to_value(uint64_t *value, uint8_t *mac)
{
	uint8_t *pmac = (uint8_t *)value;

	pmac[0] = mac[5];
	pmac[1] = mac[4];
	pmac[2] = mac[3];
	pmac[3] = mac[2];
	pmac[4] = mac[1];
	pmac[5] = mac[0];

	return;
}

static int
netdev_vf_set_config(struct netdev *dev_, const struct smap *args)
{
    struct netdev_vf *dev = netdev_vf_cast(dev_);
    const char *name = netdev_get_name(dev_);
    struct smap_node *node;
    __u32 pep0 = 0;
    uint16_t lport = 0;
    int err = 0;
    uint8_t bus = 0, device = 0, function = 0;
    uint8_t src_te_mac[ETH_ADDR_LEN];
    uint8_t tunnel_engine_mac[ETH_ADDR_LEN] = {0,1,2,3,4,5};

    /* Tunnel Engine Dflt Rule */
    struct net_mat_named_value te_set_port = {
		.name = NULL,
		.uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_MISS_DFLT_EGRESS_PORT,
		.type = NET_MAT_NAMED_VALUE_TYPE_U16,
		.value.u16 = 0,
    };
    struct net_mat_named_value te_set_dmac = {
		.name = NULL,
		.uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_DST_MAC,
		.type = NET_MAT_NAMED_VALUE_TYPE_U64,
		.value.u64 = 0,
    };
    struct net_mat_named_value te_set_smac = {
		.name = NULL,
		.uid = NET_MAT_TABLE_ATTR_NAMED_VALUE_VXLAN_SRC_MAC,
		.type = NET_MAT_NAMED_VALUE_TYPE_U64,
		.value.u64 = 0,
    };
    struct net_mat_named_value te_zero = {.name = NULL, .uid = 0, .type = 0, .value.u64 = 0};
    struct net_mat_named_value te_attribs[4];
    struct net_mat_tbl te_A_update = {.name = NULL, };
    struct net_mat_tbl te_B_update = {.name = NULL, };

    /* TCAM Table */
    struct net_mat_tbl tcam_table;
    struct net_mat_field_ref tcam_matches[] = {
		{ .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA,
                  .header = HEADER_METADATA,
                  .field = HEADER_METADATA_INGRESS_PORT,
                  .mask_type = NET_MAT_MASK_TYPE_MASK,},
		{ .instance = HEADER_INSTANCE_ETHERNET,
                  .header = HEADER_ETHERNET,
                  .field = HEADER_ETHERNET_DST_MAC,
                  .mask_type = NET_MAT_MASK_TYPE_MASK,},
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_SRC_MAC,
		  .mask_type = NET_MAT_MASK_TYPE_MASK,},
		{ .instance = HEADER_INSTANCE_ETHERNET,
		  .header = HEADER_ETHERNET,
		  .field = HEADER_ETHERNET_ETHERTYPE,
		  .mask_type = NET_MAT_MASK_TYPE_MASK,},
		{ .instance = HEADER_INSTANCE_IPV4,
		  .header = HEADER_IPV4,
		  .field = HEADER_IPV4_DST_IP,
		  .mask_type = NET_MAT_MASK_TYPE_LPM,},
                {0}};
    __u32 tcam_actions[] = {ACTION_SET_EGRESS_PORT, ACTION_FORWARD_TO_TE_A, ACTION_ROUTE_VIA_ECMP, ACTION_COUNT, 0};

    /* Tunnel Encap Table */
    struct net_mat_tbl encap_table;
    struct net_mat_field_ref tunnel_matches[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
                  .header = HEADER_ETHERNET,
                  .field = HEADER_ETHERNET_DST_MAC,
                  .mask_type = NET_MAT_MASK_TYPE_EXACT,},
		{ .instance = HEADER_INSTANCE_ETHERNET,
                  .header = HEADER_ETHERNET,
                  .field = HEADER_ETHERNET_SRC_MAC,
                  .mask_type = NET_MAT_MASK_TYPE_EXACT,},
                {0}};
    struct net_mat_field_ref tunnel_decap_matches[] = {
		{ .instance = HEADER_INSTANCE_ETHERNET,
                  .header = HEADER_ETHERNET,
                  .field = HEADER_ETHERNET_DST_MAC,
                  .mask_type = NET_MAT_MASK_TYPE_EXACT,},
		{ .instance = HEADER_INSTANCE_ETHERNET,
                  .header = HEADER_ETHERNET,
                  .field = HEADER_ETHERNET_SRC_MAC,
                  .mask_type = NET_MAT_MASK_TYPE_EXACT,},
                {0}};
    __u32 encap_actions[] = {ACTION_TUNNEL_ENCAP, ACTION_COUNT, 0};

    /* Tunnel Decap Table */
    struct net_mat_tbl decap_table;
    __u32 decap_actions[] = {ACTION_TUNNEL_DECAP, ACTION_COUNT, 0};

    /* Generic count action */
    struct net_mat_action action_cnt = { .name = "count", .uid = ACTION_COUNT, .args = NULL};

    /* Default Rule for VF */
    struct net_mat_field_ref m0 = { .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA,
			       .header = HEADER_METADATA,
			       .field = HEADER_METADATA_INGRESS_PORT,
			       .mask_type = NET_MAT_MASK_TYPE_MASK,
			       .type = NET_MAT_FIELD_REF_ATTR_TYPE_U32,
			       .v.u32.value_u32 = 1,
			       .v.u32.mask_u32 = 0xfff};
    struct net_mat_field_ref m[] = {m0, 0};
    struct net_mat_action a0 = { .name = "set_egress_port", .uid = ACTION_SET_EGRESS_PORT, .args = NULL };
    struct net_mat_action a[] = {a0, action_cnt, 0};
    struct net_mat_rule vf_dflt_rule = {
		  .table_id = 20,
		  .uid = 20,
		  .priority = 10,
		  .hw_ruleid = 0,
		  .matches = m,
		  .actions = a};
    struct net_mat_action_arg arg = {.name = "egress_port", .type = NET_MAT_ACTION_ARG_TYPE_U32, .v.value_u32 = 22};
    struct net_mat_action_arg as[] = {arg, 0};

    /* Default Rule for PF */
    struct net_mat_field_ref m_pf0 = { .instance = HEADER_INSTANCE_INGRESS_PORT_METADATA,
			       .header = HEADER_METADATA,
			       .field = HEADER_METADATA_INGRESS_PORT,
			       .mask_type = NET_MAT_MASK_TYPE_MASK,
			       .type = NET_MAT_FIELD_REF_ATTR_TYPE_U32,
			       .v.u32.value_u32 = 5,
			       .v.u32.mask_u32 = 0xffffffff};
    struct net_mat_field_ref m_pf[] = {m_pf0, 0};
    struct net_mat_action_arg arg_pf = {.name = "egress_port", .type = NET_MAT_ACTION_ARG_TYPE_U32, .v.value_u32 = 22};
    struct net_mat_action_arg args_pf[] = {arg_pf, 0};
    struct net_mat_action a_pf0 = { .name = "set_egress_port", .uid = ACTION_SET_EGRESS_PORT, .args = args_pf };
    struct net_mat_action a_pf[] = {a_pf0, action_cnt, 0};
    struct net_mat_rule pf_dflt_rule = {
		  .table_id = 20,
		  .uid = 21,
		  .priority = 10,
		  .hw_ruleid = 0,
		  .matches = m_pf,
		  .actions = a_pf};

    fm_timestamp wait = {3, 0};

    dev->tnl.dst_port = 4789;

    dev->tnl.ip_src = 0;
    dev->tnl.ip_dst = 0;

    dev->tnl.ttl = 64;
    dev->tnl.ttl_inherit = false;

    dev->tnl.tos = 0;
    dev->tnl.tos_inherit = false;

    dev->tnl.csum = true;
    dev->tnl.ipsec = false;
    dev->tnl.dont_fragment = true;

    /* TBD support per port VNI */
    dev->tnl.in_key_present = true;
    dev->tnl.in_key_flow = true;
    dev->tnl.in_key = 0;

    dev->tnl.out_key_present = true;
    dev->tnl.out_key_flow = true;
    dev->tnl.out_key = 0;

    /* setup hardware configuration channel */
    dev->hw.nsd = match_nl_get_socket();
    dev->hw.pid = netdev_vf_hw_pid_lookup();
    dev->hw.family = FLOW_FI_FAMILY;
    dev->hw.sw = FM_MAIN_SWITCH;

    SMAP_FOR_EACH (node, args) {
	char *endptr;
	int ret;

        if (!strcmp(node->key, "root")) {
	     dev->root = netdev_from_name(node->value);
	     VLOG_WARN("%s: set root netdev %p\n", name, dev->root);
	     if (!dev->root)
		VLOG_WARN("%s: no root netdev %s\n", name, node->key);
        }

        if (!strcmp(node->key, "pci")) {
	    int pf;

	    ret = sscanf(node->value, "%" SCNu8 ":%" SCNu8 ".%" SCNu8 "", &bus, &device, &function);
	    if (ret != 3) {
		VLOG_WARN("%s: invalid pci key %s\n", __func__, node->value);
	        continue;
	    }
	    VLOG_WARN("%s: use function %x:%x.%x\n", name, bus, device, function);
	}

	if (!strcmp(node->key, "lport")) {
	    ret = sscanf(node->value, "%" SCNu16 "", &lport);
	    if (ret != 1) {
		VLOG_WARN("%s: invalid lport key given %s\n", __func__, node->value);
		continue;
	    }
        }
    }

    /* match_nl_pci_lport is currently buggy so require input from cmd line */
    if (lport)
        dev->hw.vf_lport = lport;
    else
        err = match_nl_pci_lport(dev->hw.nsd, dev->hw.pid, 0, dev->hw.family,
			        bus, device, function, &dev->hw.vf_lport);

    if (err) {
        VLOG_WARN("(%x:%x.%x) does not have supported switch port\n");
	return err;
    }

    VLOG_WARN("%s: tic.remote_ip="IP_FMT" pep-lport=%i vf-lport=%i pid=%i\n",
	      name, IP_ARGS(dev->tnl.ip_dst),
	      dev->hw.pf_lport, dev->hw.vf_lport, dev->hw.pid); 

    /* Create TCAM table **hardcoded for now** */
    tcam_table.name = "tcam-ovs";
    tcam_table.uid = 20;
    tcam_table.source = 1;
    tcam_table.size = 512;
    tcam_table.matches = tcam_matches;
    tcam_table.actions = tcam_actions;
    tcam_table.attribs = NULL;
    err = match_nl_create_table(dev->hw.nsd, dev->hw.pid, 0, dev->hw.family, &tcam_table);
    if (err)
        VLOG_WARN("%s: error create tcam table failed %i\n", name, err);

    /* Create Tunnel Encap engine */
    encap_table.name = "encap-ovs";
    encap_table.uid = 30;
    encap_table.source = 2;
    encap_table.size = 512;
    encap_table.matches = tunnel_matches;
    encap_table.actions = encap_actions;
    encap_table.attribs = NULL;
    err = match_nl_create_table(dev->hw.nsd, dev->hw.pid, 0, dev->hw.family, &encap_table);
    if (err)
        VLOG_WARN("%s: error create encap table failed %i\n", name, err);

    /* Create Tunnel Decap engine */
    decap_table.name = "decap-ovs";
    decap_table.uid = 31;
    decap_table.source = 2;
    decap_table.size = 512;
    decap_table.matches = tunnel_decap_matches;
    decap_table.actions = decap_actions;
    decap_table.attribs = NULL;
    err = match_nl_create_table(dev->hw.nsd, dev->hw.pid, 0, dev->hw.family, &decap_table);
    if (err)
        VLOG_WARN("%s: error create decap table failed %i\n", name, err);

    /* Add mapping from VF to VNI */
    vf_dflt_rule.actions[0].args = as;
    arg.v.value_u32 = dev->hw.pf_lport; /* pep0 id */
    m[0].v.u32.value_u32 = dev->hw.vf_lport;
    m[0].v.u32.mask_u32 = 0xffffffff;
    err = match_nl_set_rules(dev->hw.nsd, dev->hw.pid, 0, dev->hw.family, &vf_dflt_rule);
    if (err)
        VLOG_WARN("%s: error set default vf flow failed %i\n", name, err);

    /* Add rule to map network to PF by default */
    err = match_nl_set_rules(dev->hw.nsd, dev->hw.pid, 0, dev->hw.family, &pf_dflt_rule);
    if (err)
        VLOG_WARN("%s: error set default pf flow failed %i\n", name, err);

    /* Update Tunnel Engine to use src mac address */
    netdev_get_etheraddr(dev->root, src_te_mac);
    dp_netdev_flow_mac_to_value(&te_set_dmac.value.u64, tunnel_engine_mac);
    dp_netdev_flow_mac_to_value(&te_set_smac.value.u64, src_te_mac);

    te_set_port.value.u16 = 22;
    te_attribs[0] = te_set_port;
    te_attribs[1] = te_set_dmac;
    te_attribs[2] = te_set_smac;
    te_attribs[3] = te_zero;
    te_A_update.uid = 2;
    te_B_update.uid = 3;
    te_A_update.attribs = te_attribs;
    te_B_update.attribs = te_attribs;

    match_nl_update_table(dev->hw.nsd, dev->hw.pid, 0 , dev->hw.family, &te_A_update);
    match_nl_update_table(dev->hw.nsd, dev->hw.pid, 0 , dev->hw.family, &te_B_update);

    return 0;
}

int netdev_vf_set_port_no(const struct netdev *netdev_, ofp_port_t port_no)
{
    /* And because we do not have a VF port identifier on DPDK receive and we want to
     * avoid creating our own threads...
     */
    vf_odp_port = port_no;
    VLOG_WARN("%s: odp port no %i\n", netdev_->name, vf_odp_port);
}

int netdev_vf_port(const struct netdev *netdev_)
{
    struct netdev_vf *netdev = netdev_vf_cast(netdev_);

    return netdev->hw.vf_lport;
}

static const struct netdev_class netdev_vf_class = {
    "vf",
    NULL,
    netdev_vf_run,
    netdev_vf_wait,
    netdev_vf_alloc,
    netdev_vf_construct,
    netdev_vf_destruct,
    netdev_vf_dealloc,
    netdev_vf_get_config,	/* get_config */
    netdev_vf_set_config,       /* set_config */
    netdev_vf_set_port_no,	/* set_port_no */
    NULL,                       /* get_tunnel_config */
    NULL,                       /* build header */
    NULL,                       /* push header */
    NULL,                       /* pop header */
    NULL,                       /* get_numa_id */
    NULL,                       /* set_multiq */
    netdev_vf_send,
    NULL, /*netdev_vf_send_wait,*/
    netdev_vf_set_etheraddr,
    netdev_vf_get_etheraddr,
    netdev_vf_get_mtu,
    netdev_vf_set_mtu,
    netdev_vf_get_ifindex,
    netdev_vf_get_carrier,
    netdev_vf_get_carrier_resets,
    NULL,
    netdev_vf_get_stats,
    netdev_vf_get_features,
    netdev_vf_set_advertisements,
    netdev_vf_set_policing,
    netdev_vf_get_qos_types,
    netdev_vf_get_qos_capabilities,
    netdev_vf_get_qos,
    netdev_vf_set_qos,
    netdev_vf_get_queue,
    netdev_vf_set_queue,
    netdev_vf_delete_queue,
    netdev_vf_get_queue_stats,
    netdev_vf_queue_dump_start,
    netdev_vf_queue_dump_next,
    netdev_vf_queue_dump_done,
    netdev_vf_dump_queue_stats,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    netdev_vf_get_status,
    NULL,
    netdev_vf_update_flags,
    NULL, /*netdev_vf_rxq_alloc,*/
    NULL, /*netdev_vf_rxq_construct*/
    NULL, /*netdev_vf_rxq_destruct,*/
    NULL, /*netdev_vf_rxq_dealloc,*/
    NULL, /*netdev_vf_rxq_recv,*/
    NULL, /*netdev_vf_rxq_wait,*/
    NULL, /*netdev_vf_rxq_drain,*/
};

/* Utility functions. */
static int
get_flags(const struct netdev *dev, unsigned int *flags)
{
    struct ifreq ifr;
    int error;

    *flags = 0;
    error = af_inet_ifreq_ioctl(dev->name, &ifr, SIOCGIFFLAGS, "SIOCGIFFLAGS");
    if (!error) {
        *flags = ifr.ifr_flags;
    }
    return error;
}

static int
set_flags(const char *name, unsigned int flags)
{
    struct ifreq ifr;

    ifr.ifr_flags = flags;
    return af_inet_ifreq_ioctl(name, &ifr, SIOCSIFFLAGS, "SIOCSIFFLAGS");
}

void
netdev_vf_register(void)
{
    netdev_register_provider(&netdev_vf_class);
}
