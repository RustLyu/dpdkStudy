#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <stdio.h>
#include <arpa/inet.h>

#define NUM_MBUFS (4096 - 1) //内存池的块4k

#define BURST_SIZE 32

int dpdkPortID = 0;

static const struct rte_eth_conf port_conf_default={
	.rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};
// static const struct rte_eth_conf port_conf_default = {
//     .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}};

static int n_init_port(struct rte_mempool* pool)
{
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if(nb_sys_ports <= 0)
	{
		printf("rrrrr\n");
		return -1;
	}
	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(dpdkPortID, &dev_info);
	printf("drive name:%s\n", dev_info.driver_name);
	printf("mac address:%s\n", dev_info.device->name);
	const int num_rx_queues = 1;
	const int num_tx_queues = 0;
	struct rte_eth_conf port_conf = port_conf_default;
	rte_eth_dev_configure(dpdkPortID, num_rx_queues, num_tx_queues, &port_conf);
	if(rte_eth_rx_queue_setup(dpdkPortID, 0, 128, rte_eth_dev_socket_id(dpdkPortID), NULL, pool) < 0)
	{
		printf("dddddddddd\n");
	}
	if(rte_eth_dev_start(dpdkPortID) < 0)
	{
		printf("iiiiii\n");
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	// if (rte_eal_init(argc, argv) < 0)
    // {
    //     rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    // }

	printf("0000\n");
	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 0,0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	
	// struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
    //     "mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if(mbuf_pool == NULL)
	{
		printf("kkkkkkk\n");	
	}
	printf("11111\n");
	n_init_port(mbuf_pool);
	printf("33333\n");
	while(1)
	{
		struct rte_mbuf *mbufs[BURST_SIZE];
		unsigned num_recv = rte_eth_rx_burst(dpdkPortID, 0, mbufs, BURST_SIZE);
		if(num_recv > BURST_SIZE)
		{
			printf("recv new msg\n");
		}
		if(num_recv > 0)
			printf("recv new msg count:%d\n", num_recv);
        // 对mbuf中的数据进行处理
		for(unsigned i = 0; i < num_recv; ++i)
		{
			struct rte_ether_hdr* ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
			if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
			{
				printf("type can not support:%d\n", ehdr->ether_type);
				continue;
			}
			struct rte_ipv4_hdr * iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
			if(iphdr->next_proto_id == IPPROTO_UDP)
			{
				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr*)(iphdr + 1);
				uint16_t length = ntohs(udphdr->dgram_len);
				uint16_t udp_data_len = length - sizeof(struct rte_udp_hdr) + 1;
				char buff[udp_data_len];
				memset(buff, 0,  udp_data_len);
				--udp_data_len;
				memcpy(buff , (udphdr + 1), udp_data_len);

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("src:%s : %d , ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = iphdr->dst_addr;

				printf("dst:%s : %d , %s \n", inet_ntoa(addr), ntohs(udphdr->dst_port), buff);
				rte_pktmbuf_free(mbufs[i]);
			}
			else
			{
				printf("type can not support protocol:%d\n", iphdr->next_proto_id);				
			}
		}
	}
	//rte_eal_cleanup();

	return 0;
}
