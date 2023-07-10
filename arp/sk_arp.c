#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_arp.h>

#define NUM_MBUFS (4096 - 1)
#define BURST_SIZE 32

#define N_RX_QUEUE 1
#define N_TX_QUEUE 1

#define N_RX_RING_SIZE 128
#define N_TX_RING_SIZE 128

#define  MBUF_CACHE_SIZE 250

static const struct rte_eth_conf port_conf_default={
    .rxmode = {
        .max_lro_pkt_size = RTE_ETHER_MAX_LEN
    }
};

int init_eth_port(const int port_id, struct rte_mempool* mpool)
{
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports <= 0)
    {
        return -1;
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    struct rte_eth_conf conf = port_conf_default;

    rte_eth_dev_configure(port_id, N_RX_QUEUE, N_TX_QUEUE, &conf);

    if(rte_eth_rx_queue_setup(port_id, 0, N_RX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL, mpool) < 0)
    {
        return -2;
    }

    if(rte_eth_tx_queue_setup(port_id, 0, N_TX_RING_SIZE, rte_eth_dev_socket_id(port_id), NULL) < 0)
    {
        return -3;
    }

    if(rte_eth_dev_start(port_id) < 0)
    {
        return -4;
    }
    return 0;
}
#define LOCAL_MAC ("")
int create_eth_arp_pkt(uint8_t* msg, uint8_t* d_mac, uint32_t sip, uint32_t dip)
{
    struct rte_ether_hdr* eth_hdr = (struct rte_ether_hdr*) msg;
    rte_memcpy(eth_hdr->dst_addr.addr_bytes, d_mac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth_hdr->src_addr.addr_bytes, LOCAL_MAC, RTE_ETHER_ADDR_LEN);

    struct rte_arp_hdr* arp = (struct rte_arp_hdr*)(eth_hdr + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(2);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, LOCAL_MAC, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, d_mac, RTE_ETHER_ADDR_LEN);
    
    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    //struct in_addr addr;

   // char buf[RTE_ETHER_ADDR_LEN];

   // rte_ether_format_addr(buf, ETH_ETHER_ADDR_FMT_SIZE, (struct rte_ther_addr*)&arp->arp_data.arp_sha);
   // addr.s_addr = arp->arp_data.arp_sip;
   // addr.s_addr = arp->arp_data.arp_tip;
        
}

int send_arp(struct rte_mempool* mbuf_pool, uint8_t* d_mac, uint32_t sip, uint32_t dip, int port_id)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf* mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf)
    {
        return -1;
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t* pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t*);

    create_eth_arp_pkt(pkt_data, d_mac, sip, dip);

    rte_eth_tx_burst(port_id, 0, &mbuf, 1);
    rte_pktmbuf_free(mbuf);
    return 0;
}

void print_ip_address(uint32_t ip) {
    uint8_t *byte = (uint8_t *)&ip;
    printf("%d.%d.%d.%d\n", byte[3], byte[2], byte[1], byte[0]);
}

int main(int argc, char** argv)
{

    // init eal layer
    int ret = rte_eal_init(argc, argv);
    if(ret < 0)
    {
        rte_exit(EXIT_FAILURE, "failed init eal dpdk");
    }
    
    // find cpu core
    uint16_t port_id = rte_eth_find_next_owned_by(0, RTE_ETH_DEV_NO_OWNER);
    if(port_id == RTE_MAX_ETHPORTS)
    {
        rte_exit(EXIT_FAILURE, "failed init eal dpdk");
    }
    
    // create memory pool
    struct rte_mempool* mbuf_pool = rte_pktmbuf_pool_create("mbuf_poll", NUM_MBUFS, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL)
    {
        rte_exit(EXIT_FAILURE, "111");
    }

    // config port
    ret = init_eth_port(port_id, mbuf_pool);
    if(ret  >= 0)
    {
        while(1)
        {      
            struct rte_mbuf* buf[BURST_SIZE];
            unsigned n_recv = rte_eth_rx_burst(port_id, 0, buf, BURST_SIZE);
            if(n_recv > 0)
            {
                printf("recv msg:%d\n", n_recv);
            }
            for(int i = 0; i < n_recv; ++i)
            {
                struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(buf[i], struct rte_ether_hdr*);
                if(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
                {
                    printf("recv arp command");
                    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)(eth_hdr+1);

                    print_ip_address(arp_hdr->arp_data.arp_tip);
                
                    if(arp_hdr->arp_data.arp_tip == "192.168.0.127")
                    {
                        printf("recv: ip equal\n");
                    }
                    else
                    {
                        printf("recv: ip do not equal%d\n", arp_hdr->arp_data.arp_tip);
                    }
                }
            
                rte_pktmbuf_free(buf[i]);
            }
        }
    }

    
    rte_eal_cleanup();
    return 0;
}
