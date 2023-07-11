#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <inttypes.h>
#include <rte_log.h>

#define NUM_MBUFS (4096 - 1)
#define BURST_SIZE 32

#define N_RX_QUEUE 1
#define N_TX_QUEUE 1

#define N_RX_RING_SIZE 128
#define N_TX_RING_SIZE 128

#define  MBUF_CACHE_SIZE 250

#define LOCAL_MAC ("00:0c:29:e4:9c:99")

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
    printf("%d.%d.%d.%d\n", byte[0], byte[1], byte[2], byte[3]);
}

void set_eth_hdr(struct rte_ether_hdr* hdr)
{}

void set_ipv4_hdr(struct rte_ipv4_hdr* hdr)
{}

void set_icmp_hdr(struct rte_icmp_hdr* hdr)
{}

int main(int argc, char** argv)
{

    // init eal layer
    int ret = rte_eal_init(argc, argv);
    if(ret < 0)
    {
        rte_exit(EXIT_FAILURE, "failed init eal dpdk");
    }
    rte_log_set_level(RTE_LOG_DEBUG, 0); 
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

    // start rx/tx data
    if(ret  >= 0)
    {
        while(1)
        {      
            struct rte_mbuf* buf[BURST_SIZE];
            // struct rte_mbuf* tx_buf[BURST_SIZE];
            unsigned n_recv = rte_eth_rx_burst(port_id, 0, buf, BURST_SIZE);
            if(n_recv > 0)
            {
                //printf("recv msg:%d\n", n_recv);
            }
            for(int i = 0; i < n_recv; ++i)
            {
                struct rte_ether_hdr* eth_hdr = rte_pktmbuf_mtod(buf[i], struct rte_ether_hdr*);

                /// ARP
                if(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP))
                {
                    //printf("recv arp command");
                    struct rte_arp_hdr* arp_hdr = (struct rte_arp_hdr*)(eth_hdr+1);

                    //print_ip_address(arp_hdr->arp_data.arp_tip);
                
                    if(arp_hdr->arp_data.arp_tip == "192.168.0.127")
                    {
                        printf("recv: ip equal\n");
                    }
                    else
                    {
                        //printf("recv: ip do not equal%d\n", arp_hdr->arp_data.arp_tip);
                    }
                }
                else
                {
                    struct rte_ipv4_hdr* ip_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
                    /// ICMP
                    if(ip_hdr->next_proto_id == IPPROTO_ICMP)
                    {

                        struct rte_icmp_hdr* icmp_hdr = (struct rte_icmp_hdr*)(ip_hdr + 1);

                        struct rte_mbuf* tx_pkt = rte_pktmbuf_alloc(mbuf_pool);

                        struct rte_ether_hdr* tx_eth_hdr = rte_pktmbuf_mtod(tx_pkt, struct rte_ether_hdr*);
                        struct rte_ipv4_hdr* tx_ip_hdr = (struct rte_ipv4_hdr*)(tx_eth_hdr + 1);
                        struct rte_icmp_hdr* tx_icmp_hdr = (struct rte_icmp_hdr*)(tx_ip_hdr + 1);
                        //set_eth_hdr(eth_hdr);
                        // build eth hdr
                        // rte_memcpy(&tx_eth_hdr->src_addr.addr_bytes, LOCAL_MAC, RTE_ETHER_ADDR_LEN);
                        rte_ether_addr_copy(&eth_hdr->src_addr.addr_bytes, &tx_eth_hdr->dst_addr.addr_bytes);
                        rte_ether_addr_copy(&eth_hdr->dst_addr.addr_bytes, &tx_eth_hdr->src_addr.addr_bytes);
                        tx_eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);//eth_hdr->ether_type;
                        
                        // build ipv4 hdr
                        tx_ip_hdr->version_ihl = 0x45; //(4 << 4) | (5 & 0xF); // version is ipv4, hdr len 5
                        tx_ip_hdr->type_of_service = 0;
                        tx_ip_hdr->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
                        tx_ip_hdr->packet_id = 0;//ip_hdr->packet_id;
                        tx_ip_hdr->fragment_offset = 0;//rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
                        tx_ip_hdr->time_to_live = 64;
                        tx_ip_hdr->next_proto_id = IPPROTO_ICMP;
                        tx_ip_hdr->hdr_checksum = 0;
                        tx_ip_hdr->src_addr = ip_hdr->dst_addr;
                        tx_ip_hdr->dst_addr = ip_hdr->src_addr;
                        tx_ip_hdr->hdr_checksum = rte_ipv4_cksum(tx_ip_hdr);

                        print_ip_address(tx_ip_hdr->src_addr);
                        print_ip_address(tx_ip_hdr->dst_addr);
                        
                        char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
                        rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, &tx_eth_hdr->src_addr.addr_bytes);
                        printf("sd src MAC address: %s\n", mac_str);
                        
                        memset(mac_str, RTE_ETHER_ADDR_FMT_SIZE, 0);
                        rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, &tx_eth_hdr->dst_addr.addr_bytes);
                        printf("sd dst MAC address: %s\n", mac_str);

                        memset(mac_str, RTE_ETHER_ADDR_FMT_SIZE, 0);
                        rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, &eth_hdr->dst_addr.addr_bytes);
                        printf("rc dst MAC address: %s\n", mac_str);
                        memset(mac_str, RTE_ETHER_ADDR_FMT_SIZE, 0);
                        rte_ether_format_addr(mac_str, RTE_ETHER_ADDR_FMT_SIZE, &eth_hdr->src_addr.addr_bytes);
                        printf("rc src MAC address: %s\n", mac_str);

                        // set icmp hdr
                        tx_icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
                        tx_icmp_hdr->icmp_code = 0;
                        tx_icmp_hdr->icmp_ident = icmp_hdr->icmp_ident;
                        tx_icmp_hdr->icmp_seq_nb = icmp_hdr->icmp_seq_nb;
                        tx_icmp_hdr->icmp_cksum = 0;
                        tx_icmp_hdr->icmp_cksum = rte_raw_cksum(tx_icmp_hdr, sizeof(struct rte_icmp_hdr));
                        //set_ipv4_hdr(ip_hdr);
                        //set_icmp_hdr(icmp_hdr);
                        //tx_buf[0] = tx_pkt;
                        const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
                        tx_pkt->pkt_len = total_length;
                        tx_pkt->data_len = total_length;
                        int n_tx = rte_eth_tx_burst(port_id, 0, &tx_pkt, 1);
                        if(n_tx < 1)
                        {
                            rte_pktmbuf_free(tx_pkt);
                        }
                        else
                        {
                            
                            uint64_t error_no = 0;//rte_eth_tx_burst_error(port_id, 0);
                            printf("recv: icmp msg failed error no:\n");
                        }
                        printf("recv: icmp msg\n");
                    }
                }
            
                rte_pktmbuf_free(buf[i]);
            }
        }
    }

    
    rte_eal_cleanup();
    return 0;
}
