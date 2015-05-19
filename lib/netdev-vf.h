/* We use the vf src mac to identify packets that have been received from
 * the virtual function then we set the in_port correctly. This is really
 * ugly. We should put the info in the descriptor and then set it correctly
 * in DPDK _or_ have a queue per vf?
 */
extern uint8_t vf_eth_src[ETH_ADDR_LEN];
extern int vf_odp_port;

void netdev_vf_register(void);
uint32_t netdev_vf_lport(struct netdev *netdev_);
