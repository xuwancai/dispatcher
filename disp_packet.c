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
#include "rte_eal.h"

#include "disp_prase_config.h"
#include "disp_packet.h"

unsigned long long packet_num = 0;

static inline u_int16_t get_align_u16(u_int8_t *data)
{
#ifdef AVOID_ALIGN_BYTE
	return (u_int16_t)((data[0] << 8) | (data[1]));
#else
	return *((u_int16_t *)data);
#endif
}

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

static int dis_parse_ipv6_pkt(u_int8_t *raw_packt, int offset)
{
	int worker_id = -1;
	struct ipv6_frag_hdr *fhdr;
	u_int8_t nexthdr;
	struct ipv6_opt_hdr *hp;
	struct dis_five_tuple tuple;
	u_int8_t *ip_head = raw_packt + offset;
	struct ipv6_hdr *hdr = (struct ipv6_hdr *)ip_head;

	if (hdr->version != 6) {
		worker_id = 1;
		goto ret;
	}

	memcpy(tuple.sip.ipv6_addr, hdr->src_addr, 16);
	memcpy(tuple.dip.ipv6_addr, hdr->dst_addr, 16);
	tuple.iptype = 6;

	nexthdr = hdr->nexthdr;
	hp = (struct ipv6_opt_hdr *)(ip_head + sizeof(struct ipv6_hdr));

	/* 处理扩展头部 */
	while (ipv6_ext_hdr(nexthdr)) {
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
		worker_id = 1;
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
	worker_id = child_table_check(&tuple);
	if(worker_id != -1)
		goto ret;

	worker_id = dispatch_task_flow(&tuple);
ret:
	return worker_id;
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

int pre_deal_pkt(u_int8_t *raw_packet, int raw_packet_len)
{
	u_int8_t *ip_head;
	int worker_id;
	int ip_head_offset = 14;
	int vlan_flag = 0;
	int pkt_type;
	int ipsec_flag = 0;	
	struct iphdr *ip;
	struct dis_five_tuple tuple;
	
	pkt_type = is_ip_packet(raw_packet, &vlan_flag);
	if (pkt_type == NON_IP_PACKET) {
		worker_id = 1;
		goto ret;
	}

	switch(pkt_type) {
		case PPPOE_IP_PACKET:
			ip_head_offset += 8;
			break;
		case MPLS_IP_PACKET:
			while (!(*(raw_packet + ip_head_offset + 2) & 0x1)) {
				ip_head_offset += 4;
			}
			ip_head_offset += 4;
			break;
		case BARE_IP_PACKET:
		case IPV6_IP_PACKET:
		default:
			break;
	}

	if (vlan_flag) {
		ip_head_offset += sizeof(struct dispatch_vlanhdr);
	}

	ip_head = raw_packet + ip_head_offset;

	ip = (struct iphdr *)ip_head;
	if (6 == ip->version) {
		worker_id = dis_parse_ipv6_pkt(raw_packet, ip_head_offset);
		goto ret;
	}

	if (ip->version != 4 || ip->protocol == 1 /* ICMP */){
		worker_id = 1;
		goto ret;
	}

	tuple.sip.ipv4_addr = ip->saddr;
	tuple.dip.ipv4_addr = ip->daddr;
	tuple.iptype = 4;
	tuple.protocol = ip->protocol;

	/* 碎片按sip dip ip->id 3元计算 */
	if (unlikely(isfragment(htons(ip->frag_off)))){
		tuple.sport = ip->id;
		tuple.dport = 0;
		tuple.tuple = 3;

		worker_id = dispatch_task_flow(&tuple);
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
		worker_id = packet_num % dc->app_num + 1;
		if (!(ip->frag_off & htons(IP_MF|IP_OFFSET)))
			goto ret;
	}

#if 1
	worker_id = child_table_check(&tuple);
	if(worker_id != -1)
		goto ret;
#endif
	worker_id = dispatch_task_flow(&tuple);

ret:
	return worker_id;
}

