#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096 - 1) //内存池的块4k

#define BURST_SIZE 32

int gDpdkPortId = 0; //定义端口的id

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};

static void ng_init_port(struct rte_mempool *mbuf_pool)
{
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0)
        return;
        //rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);
    const int num_rx_queues = 1; //接收队列，最多有8个，这里只设置1个接收队列数量
    const int num_tx_queues = 0;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool) < 0)
    {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    // 启动eth0
    if (rte_eth_dev_start(gDpdkPortId) < 0)
    {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

int main(int argc, char *argv[])
{
    // 初始化环境，检查内存、CPU相关的设置，主要是巨页、端口的设置
    if (rte_eal_init(argc, argv) < 0)
    {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    // 内存池初始化，发送和接收的数据都在内存池里
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (NULL == mbuf_pool)
    {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    // 启动dpdk
    ng_init_port(mbuf_pool);

    while (1)
    {
        // 接收数据
        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE)
        {
            // 溢出
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }
        if(num_recvd > 0)
			printf("recv new msg count:%d\n", num_recvd);
        // 对mbuf中的数据进行处理
        unsigned i = 0;
        for (i = 0; i < num_recvd; i++)
        {
            // 得到以太网中的数据
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            // 如果不是ip协议
            if (ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            {
                continue;
            }
            struct rte_ipv4_hdr *iphdr =
                rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

            // 接收udp的数据帧
            if (iphdr->next_proto_id == IPPROTO_UDP)
            {
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr) + 1;

                uint16_t length = ntohs(udphdr->dgram_len);
                // udp data copy to buff
                uint16_t udp_data_len = length - sizeof(struct rte_udp_hdr) + 1;
                char buff[udp_data_len];
                memset(buff, 0, udp_data_len);
                --udp_data_len;
                memcpy(buff, (udphdr + 1), udp_data_len);

                //源地址
                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

                //目的地址+数据长度+数据内容
                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, %s\n",
                       inet_ntoa(addr), ntohs(udphdr->dst_port), buff);

                // 用完放回内存池
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
}
