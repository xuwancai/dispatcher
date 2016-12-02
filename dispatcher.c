#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>
#include <linux/if_ether.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "rte_common.h"
#include "rte_log.h"
#include "rte_malloc.h"
#include "rte_memory.h"
#include "rte_memcpy.h"
#include "rte_memzone.h"
#include "rte_eal.h"
#include "rte_per_lcore.h"
#include "rte_launch.h"
#include "rte_atomic.h"
#include "rte_cycles.h"
#include "rte_prefetch.h"
#include "rte_lcore.h"
#include "rte_per_lcore.h"
#include "rte_branch_prediction.h"
#include "rte_interrupts.h"
#include "rte_random.h"
#include "rte_debug.h"
#include "rte_ether.h"
#include "rte_ethdev.h"
#include "rte_mempool.h"
#include "rte_mbuf.h"

#include "disp_prase_config.h"
#include "disp_common.h"
#include "dispatcher.h"

#define DIPATCHER_RX_DESC_DEFAULT 128
#define DIPATCHER_TX_DESC_DEFAULT 512
#define MEMPOOL_CACHE_SIZE 256
#define MAX_PKT_BURST 32

struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

int do_cleanup = 0;
int global_serial_no=0;

#if 0
/* copy from linux/ip.h*/
struct ip_auth_hdr {
	__u8  nexthdr;
	__u8  hdrlen;		/* This one is measured in 32 bit units! */
	__be16 reserved;
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  auth_data[0];	/* Variable len but >=4. Mind the 64 bit alignment! */
};

struct ip_esp_hdr {
	__be32 spi;
	__be32 seq_no;		/* Sequence number */
	__u8  enc_data[0];	/* Variable len but >=8. Mind the 64 bit alignment! */
};
/* end */

int dispatch_task_average(char *pkt, int len, u_int8_t *ip_head, int num)
{
	static int id = 0;
	id = (id + 1) % num;
	//return id + 1;
	return id;
}

int dispatch_task_ip(char *pkt, int len, u_int8_t *ip_head, int num)
{
	struct iphdr *ip = (struct iphdr *)ip_head;
	unsigned int sip = ntohl(ip->saddr);
	unsigned int dip = ntohl(ip->daddr);
	unsigned int core = (unsigned)(sip + dip) % num;
	return core;
}

#define DIS_XOR(n) (((n >> 24) & 0xff) ^ ((n >> 16) & 0xff) \
					^ ((n >> 8) & 0xff) ^  (n & 0xff))
static int dispatch_task_flow(struct dis_five_tuple *t)
{
	unsigned int core = 0;
	unsigned short hash;

	if (3 == t->tuple) {
		unsigned short sport;
		if (t->sport)
			sport = t->sport;
		else
			sport = t->protocol;
		if (t->iptype == 4)
	    	hash = DIS_XOR(t->sip.ipv4_addr) ^ DIS_XOR(t->dip.ipv4_addr)
					^ ((sport >> 8) & 0xff) ^ (sport & 0xff);
		else
			hash = DIS_XOR(t->sip.ipv6_addr[0]) ^ DIS_XOR(t->sip.ipv6_addr[1])
					^ DIS_XOR(t->sip.ipv6_addr[2]) ^ DIS_XOR(t->sip.ipv6_addr[3])
					^ DIS_XOR(t->dip.ipv6_addr[0]) ^ DIS_XOR(t->dip.ipv6_addr[1])
					^ DIS_XOR(t->dip.ipv6_addr[2]) ^ DIS_XOR(t->dip.ipv6_addr[3])
					^ ((sport >> 8) & 0xff) ^ (sport & 0xff);
		core = hash % dc->app_num;
	} else if (5 == t->tuple) {
		if (t->iptype == 4)
		    hash = DIS_XOR(t->sip.ipv4_addr) ^ DIS_XOR(t->dip.ipv4_addr)
					^ ((t->sport >> 8) & 0xff) ^ (t->sport & 0xff)
					^ ((t->dport >> 8) & 0xff) ^ (t->dport & 0xff);
		else
			hash = DIS_XOR(t->sip.ipv6_addr[0]) ^ DIS_XOR(t->sip.ipv6_addr[1])
					^ DIS_XOR(t->sip.ipv6_addr[2]) ^ DIS_XOR(t->sip.ipv6_addr[3])
					^ DIS_XOR(t->dip.ipv6_addr[0]) ^ DIS_XOR(t->dip.ipv6_addr[1])
					^ DIS_XOR(t->dip.ipv6_addr[2]) ^ DIS_XOR(t->dip.ipv6_addr[3])
					^ ((t->sport >> 8) & 0xff) ^ (t->sport & 0xff)
					^ ((t->dport >> 8) & 0xff) ^ (t->dport & 0xff);
		core = hash % dc->app_num;
	} else {
		printf("%s Wrong tuple!\n", __FUNCTION__);
	}

	return core + 1;
}

static inline void prefetch(const void *addr)
{
#if defined(CONFIG_CPU_CAVIUM_OCTEON)
	__builtin_prefetch(addr);
#else
	__asm__ __volatile__(
			"prefetcht0 %[addr]"
			: [addr] "+m" (*(volatile unsigned long *)addr));
#endif
}

static inline u_int16_t get_align_u16(u_int8_t *data)
{
#ifdef AVOID_ALIGN_BYTE
	return (u_int16_t)((data[0] << 8) | (data[1]));
#else
	return *((u_int16_t *)data);
#endif
}

#define NEXTHDR_HOP		0	/* Hop-by-hop option header. */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */

static int ipv6_ext_hdr(u_int8_t nexthdr)
{
	/*
	 * find out if nexthdr is an extension header or a protocol
	 */
	return ((nexthdr == NEXTHDR_HOP)	||
		 (nexthdr == NEXTHDR_ROUTING)	||
		 (nexthdr == NEXTHDR_FRAGMENT)	||
		 (nexthdr == NEXTHDR_AUTH)	||
		 (nexthdr == NEXTHDR_NONE)	||
		 (nexthdr == NEXTHDR_DEST));
}

struct ipv6_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u_int8_t priority:4,
			version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u_int8_t version:4,
			priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	u_int8_t flow_lbl[3];
	u_int16_t payload_len;  /**< IP packet length - includes sizeof(ip_header). */
	u_int8_t  nexthdr;      /**< Protocol, next header. */
	u_int8_t  hop_limits;   /**< Hop limits. */
	u_int32_t  src_addr[4]; /**< IP address of source host. */
	u_int32_t  dst_addr[4]; /**< IP address of destination host(s). */
} __attribute__((__packed__));

struct ipv6_opt_hdr {
	u_int8_t nexthdr;
	u_int8_t hdrlen;
	/* 
	 * TLV encoded option data follows.
	 */
} __attribute__((__packed__));

struct ipv6_frag_hdr {
	u_int8_t nexthdr;
	u_int8_t reserved;
	u_int16_t frag_off;
	u_int32_t identification;
};

static int dis_parse_ipv6_pkt(u_int8_t *raw_packt, int offset)
{
	int ret_worker_id = -1;
	struct ipv6_frag_hdr *fhdr;
	u_int8_t nexthdr;
	struct ipv6_opt_hdr *hp;
	struct dis_five_tuple tuple;
	u_int8_t *ip_head = raw_packt + offset;
	struct ipv6_hdr *hdr = (struct ipv6_hdr *)ip_head;

	if (hdr->version != 6) {
		ret_worker_id = 1;
		goto ret;
	}

	memcpy(tuple.sip.ipv6_addr, hdr->src_addr, 16);
	memcpy(tuple.dip.ipv6_addr, hdr->dst_addr, 16);
	tuple.iptype = 6;

	nexthdr = hdr->nexthdr;
	hp = (struct ipv6_opt_hdr *)(ip_head + sizeof(struct ipv6_hdr));

	/* 处理扩展头部 */
	while(ipv6_ext_hdr(nexthdr)) {
		int hdrlen;

		if (nexthdr == NEXTHDR_NONE) {
			tuple.sport = 0;
			tuple.dport = 0;
			tuple.tuple = 3;
			tuple.protocol = nexthdr;
			goto rest;
		}

		if (nexthdr == NEXTHDR_FRAGMENT) {
			fhdr = (struct ipv6_frag_hdr *)hp;
			tuple.sport = ntohl(fhdr->identification) & 0xffff;
			tuple.dport = 0;
			tuple.tuple = 3;
			tuple.protocol = nexthdr;
			goto rest;

		} else if (nexthdr == NEXTHDR_AUTH)
			hdrlen = (hp->hdrlen+2)<<2;
		else
			hdrlen = ((hp)->hdrlen+1) << 3;

		nexthdr = hp->nexthdr;
		hp = (struct ipv6_opt_hdr *)((char *)hp + hdrlen);
	}

	if (nexthdr == NEXTHDR_ICMP) {
		ret_worker_id = 1;
		goto ret;
	}

	if (nexthdr == 6 || nexthdr == 17) { /* udp or tcp */
		struct tcphdr *tcp = (struct tcphdr *)hp;
		tuple.sport = tcp->source;
		tuple.dport = tcp->dest;
		tuple.protocol = nexthdr;
		tuple.tuple = 5;
	} else {
		tuple.sport = 0;
		tuple.dport = 0;
		tuple.protocol = nexthdr;
		tuple.tuple = 3;
	}
	
rest:
	ret_worker_id = child_table_check(&tuple);
	if(ret_worker_id != -1)
		goto ret;

	ret_worker_id = dispatch_task_flow(&tuple);
ret:
	return ret_worker_id;
}

static inline int is_ip_packet(u_int8_t *raw_packet, int *vlan_flag)
{
	u_int8_t *do_offset = NULL;
	int pkt_type = NON_IP_PACKET;
	struct ethhdr *eth_hdr = (struct ethhdr *)raw_packet;
	u_int16_t proto_tmp = ntohs(eth_hdr->h_proto);
	u_int16_t eth_proto_tmp = 0;
	struct dispatch_vlanhdr *vlanhdr = NULL;
	u_int16_t ppp_protocol = 0;

	switch(proto_tmp)
	{
		case 0x8100:
			vlanhdr = (struct dispatch_vlanhdr *)(eth_hdr + 1);
			eth_proto_tmp = ntohs(vlanhdr->vh_proto);
			*vlan_flag = 1;
			do_offset = (u_int8_t *)(eth_hdr + 1) + sizeof(struct dispatch_vlanhdr);
			break;
		default:
			eth_proto_tmp = proto_tmp;
			do_offset = (u_int8_t *)(eth_hdr + 1);
			break;
	}

	if (eth_proto_tmp < 1536) { /* ETH_P_802_2_LLC_PACKET */
		goto ret;
	}

	switch(eth_proto_tmp)
	{
		case 0x0800:
			pkt_type = BARE_IP_PACKET;
			break;
		case 0x8847:
		case 0x8848:
			pkt_type = MPLS_IP_PACKET;
			break;
		case 0x8863:
		case 0x8864:
			ppp_protocol = ntohs(get_align_u16(do_offset + 6));
			if(ppp_protocol == 0x21)
			{
				pkt_type = PPPOE_IP_PACKET;
			}
			else
			{
				pkt_type = NON_IP_PACKET;
			}
			break;
		case 0x86dd:
			pkt_type = IPV6_IP_PACKET;
			break;
	}
ret:
	return pkt_type;
}

unsigned long long packet_num = 0;
int pre_deal_pkt(u_int8_t *raw_packet, int raw_packet_len,
		struct nm_pkt_header *nph)
{
	int ret_worker_id = -1;
	u_int8_t *ip_head = raw_packet;
	struct iphdr *ip = NULL;
	int ip_head_offset = 14;
	int vlan_flag = 0;
	int pkt_type = 0;
	struct dis_five_tuple tuple;
	int ipsec_flag = 0;
	
	pkt_type = is_ip_packet(raw_packet, &vlan_flag);

	if (pkt_type == NON_IP_PACKET) {
		ret_worker_id = 1;
		return ret_worker_id;
	}

	switch(pkt_type) //
	{
		case PPPOE_IP_PACKET:
			ip_head_offset += 8;
			break;
		case MPLS_IP_PACKET:
			while (!(*(raw_packet + ip_head_offset + 2) & 0x1)){
				ip_head_offset += 4;
			}
			ip_head_offset += 4;
			break;
		case BARE_IP_PACKET:
		case IPV6_IP_PACKET:
		default:
			break;
	}

	if(vlan_flag)
	{
		ip_head_offset += sizeof(struct dispatch_vlanhdr);
	}

	ip_head = raw_packet + ip_head_offset;

	ip = (struct iphdr *)ip_head;
	if (6 == ip->version) {
		ret_worker_id = dis_parse_ipv6_pkt(raw_packet, ip_head_offset);
		goto ret;
	}

	if(ip->version != 4 || ip->protocol == 1 /* ICMP */)
	{
		ret_worker_id = 1;
		goto ret;
	}

	tuple.sip.ipv4_addr = ip->saddr;
	tuple.dip.ipv4_addr = ip->daddr;
	tuple.iptype = 4;
	tuple.protocol = ip->protocol;

	/* 碎片按sip dip ip->id 3元计算 */
	if(unlikely(isfragment(htons(ip->frag_off))))
	{
		tuple.sport = ip->id;
		tuple.dport = 0;
		tuple.tuple = 3;

		ret_worker_id = dispatch_task_flow(&tuple);
		goto ret;
	}

	if (ip->protocol == 6 || ip->protocol == 17) { /* TCP and UDP*/
		struct tcphdr *tcp = (struct tcphdr *)(ip_head + (ip->ihl << 2));
		tuple.sport = tcp->source;
		tuple.dport = tcp->dest;
		tuple.tuple = 5;
	} 
	/* add ipsec, by daixijiang */
	else if (ip->protocol == 50) { /* ESP */
		struct ip_esp_hdr *esph = (struct ip_esp_hdr *)(ip_head + (ip->ihl << 2));
		tuple.sport = (esph->spi & 0xFFFF0000) >> 16;
		tuple.dport = esph->spi & 0x0000FFFF;
		tuple.tuple = 5;
		packet_num++;
		ipsec_flag = 1;
	} else if (ip->protocol == 51) { /* AH */
		struct ip_auth_hdr *ah = (struct ip_auth_hdr *)(ip_head + (ip->ihl << 2));
		tuple.sport = (ah->spi & 0xFFFF0000) >> 16;
		tuple.dport = ah->spi & 0x0000FFFF;
		tuple.tuple = 5;
		packet_num++;
		ipsec_flag = 1;
	} 
	/* end */
#if 0
	else if (ip->protocol == 47) { /* GRE */
		proto_gre_decode(ip, &tuple);
	}
#endif
	else { /* 其他类型的ip报文按3元组分，查期望连接哈希表sport和dport取值0 */
		tuple.sport = 0;
		tuple.dport = 0;
		tuple.tuple = 3;
	}
	if (packet_num && ipsec_flag) {
		ret_worker_id = (packet_num % dc->app_num)+1;
		if (!(ip->frag_off& htons(IP_MF|IP_OFFSET)))
			goto ret;
	}
#if 1
	ret_worker_id = child_table_check(&tuple);
	if(ret_worker_id != -1)
		goto ret;
#endif
	ret_worker_id = dispatch_task_flow(&tuple);
ret:
	return ret_worker_id;
}

int packet_callback(struct nm_pkt_header *nph)
{
	int ret_worker_id = 0;

	if((unsigned int)nph->len < sizeof(struct ethhdr))
	{
		goto err;
	}

	ret_worker_id = pre_deal_pkt(nph->pkt, nph->len, nph);
	if((ret_worker_id < 1) || (ret_worker_id > dc->app_num))
	{
		goto err;
	}
	nph->o_ifindex = (ret_worker_id - 1) * dc->thread_num + nph->tidx + 1;
	//nph->o_ifindex += nph->tidx * 4;
	if (0 == nm_send_pkt(nph)) {
		//(dp->send_ok_packet[ret_worker_id - 1])++;
	}

	return 0;
err:
	return -1;
}
#endif

static int detect_process(char * process_name)
{
	FILE *ptr;
	char buff[64] = {0};
	char ps[64];
	sprintf(ps,"ps | grep -c %s", process_name);
	if((ptr = popen(ps, "r")) != NULL)
	{
		while (fgets(buff, sizeof(buff), ptr) != NULL)
		{
			if(atoi(buff) >= 2)
			{
				pclose(ptr);
				return 0;
			}
		}
	}else
		return -1;
	pclose(ptr);
	return -1;
}


void packet_handle(struct dispatcher_item *dispatcher_item)
{
    uint32_t i;
    uint32_t portid;
    uint32_t nb_rx;
    static uint32_t total = 0;
    static uint64_t total_last = 0;
    
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	
	for (i = 0; i < dispatcher_item->phy_port_num; i++) {

		portid = dispatcher_item->phy_port_id[i];
		nb_rx = rte_eth_rx_burst((uint8_t) portid, 0, pkts_burst, MAX_PKT_BURST);
        total += nb_rx;
	}

    if (total - total_last > 1000) {
        total_last = total;
        printf("recv packet: portid=%d, num=%d \n", portid, total);
    }

	return;
}

static rte_atomic32_t thread_init = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t thread_exit = RTE_ATOMIC32_INIT(0);

void *dispatch_main(void *arg)
{
	int ret;

	struct dispatcher_item *dispatcher_item = (struct dispatcher_item *)arg;
	
	rte_thread_init_slave(dispatcher_item->affinity_core);

	/* read on our pipe to get commands */
    rte_atomic32_inc(&thread_init);
    while (rte_atomic32_read(&thread_init) != dc->dispatcher_num){
       rte_pause();
    }
     
	/* 最后一个线程写入 */
	if (dispatcher_item->item_id == (dc->dispatcher_num - 1)) {
		ret = system("echo 1 > /tmp/dispatcher.ok");
		if (WIFSIGNALED(ret) && (WTERMSIG(ret)==SIGINT || WTERMSIG(ret)==SIGQUIT)) {
			printf("Can not create file /tmp/disptcher.ok!\n");
		}
	}

    #if 0
	do { /*waiting for app_main to initialize the share memory */
		sleep(1);
		//printf("Pid %d, waiting...\n", getpid());
	} while (-1 == detect_process("vtysh"));
    #endif
    
	while(1) {
		if (unlikely(do_cleanup)) {
		    rte_atomic32_inc(&thread_exit);
			exit(0);
		}
	    packet_handle(dispatcher_item);
	}
	
	exit(0);
}

void hup(int signo)
{
	//print_dispatcher_profile();
	return;
}

void report_msg(int signo)
{
	//print_dispatcher_profile();
}

//for signal()
void setcleanup(int sig)
{
	do_cleanup = 1;
}

//for set_signal()
void set_cleanup(int signo, siginfo_t *sig, void *data)
{
	do_cleanup = 1;
}

void clean_interface(void)
{
    uint32_t portid;
	for (portid = 0; portid < dc->phy_port_num; portid++) {
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	
	return;
}

void clean_global(void)
{
	clean_interface();
	clean_dispatcher_conf();
	return;
}

static void signal_init(void)
{
	//setsignal(SIGTERM, set_cleanup);
	//setsignal(SIGINT, set_cleanup);
	signal(SIGTERM, setcleanup);
	signal(SIGINT, setcleanup);
	//signal(SIGSEGV, core_dump);
	signal(SIGHUP, hup);
	signal(50, report_msg);	
	
	disp_backtrace_init();

	return;
}

static int init_dispatcher(void)
{
	if (prase_dispatcher_conf("dispatcher.xml")) 
		return -1;

	signal_init();
	
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}


struct rte_mempool * pktmbuf_pool = NULL;
static int init_interface() 
{
	int ret;
	int i;
    uint32_t portid;
	struct phy_port_item *phy_port_item;
	struct rte_eth_dev_info dev_info;

	/* create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("dispatcher_mbuf_pool", 8192,
							MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
							rte_socket_id());
	if (pktmbuf_pool == NULL) {
		printf("Cannot init mbuf pool\n");
		return -1;
	}

	/* Initialise each port */
	for (portid = 0; portid < dc->phy_port_num; portid++) {
        phy_port_item = dc->phy_port_item + portid;

        rte_eth_dev_info_get(portid, &dev_info);
        
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);	
		fflush(stdout);
		
		ret = rte_eth_dev_configure(portid, phy_port_item->rx_queue_num, 
									phy_port_item->tx_queue_num, &port_conf);
		if (ret < 0) {
			printf("Cannot configure device: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        
		ret = rte_eth_rx_queue_setup(portid, 0, DIPATCHER_RX_DESC_DEFAULT,
					     rte_eth_dev_socket_id(portid), NULL, pktmbuf_pool);
		if (ret < 0) {
			printf("rte_eth_rx_queue_setup: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}

		ret = rte_eth_tx_queue_setup(portid, 0, DIPATCHER_TX_DESC_DEFAULT,
					rte_eth_dev_socket_id(portid), NULL);
		if (ret < 0) {
			printf("rte_eth_tx_queue_setup: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			printf("rte_eth_dev_start: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}
		printf("done: \n");

        printf("mac: ");
        for (i=0; i<ETHER_ADDR_LEN; i++) {
            if (i == ETHER_ADDR_LEN-1)
               printf("0x%02x", ports_eth_addr[portid].addr_bytes[i]);
            else
               printf("0x%02x:", ports_eth_addr[portid].addr_bytes[i]);
        }
        printf("\n");
        
		rte_eth_promiscuous_enable(portid);	
	}

	check_all_ports_link_status(dc->phy_port_num);
	
	return 0;
}

/* 初始化dispatcher与app main的队列 */
int init_queue(void)
{
    return 0;
}

int main(int argc, char *argv[])
{
    int i;
	int ret;
	int core_id;
	struct dispatcher_item *dispatcher_item;
	char thread_name[RTE_MAX_THREAD_NAME_LEN];
	
	if (argc > 1) {
		global_serial_no = atoi(argv[1]);
	}

	if (sysconf(_SC_NPROCESSORS_ONLN) < 3) {
		ret = system("echo 1 > /tmp/dispatcher.ok");
		if (WIFSIGNALED(ret) && 
			(WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT)) {
			printf("Can not create file /tmp/disptcher.ok!\n");
		}
		exit(0); /* don't run dispatcher on ATOM platform */
	}
	
	if (init_dispatcher())
		goto err;

	if (rte_eal_init_custom(dc->master_affinity))
		goto err;
		
	if (init_interface())
		goto err;

    for (i = 0; i < dc->dispatcher_num; i++) {
	    dispatcher_item = dc->dispatcher_item + i;
		core_id = dispatcher_item->affinity_core;
		ret = pthread_create(&lcore_config[core_id].thread_id, NULL,
						     dispatch_main, dispatcher_item);
		if (ret != 0) {
			printf("Cannot create thread\n");
			goto err;
		}
			
		snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "dispatcher%d", i);
		ret = rte_thread_setname(lcore_config[i].thread_id, thread_name);
		if (ret != 0)
			printf("Cannot set name for lcore thread\n");
	}
				
    while (1) {
  		sleep(1);
        if (rte_atomic32_read(&thread_exit) == dc->dispatcher_num)
            break;
    }
    
	clean_global();
	return 0;
err:
	return -1;
}
