#ifndef _DISP_PACKET_H
#define _DISP_PACKET_H

#include <stdio.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <asm/byteorder.h>

#include "hash.h"

#define NEXTHDR_HOP		    0	/* Hop-by-hop option header. */
#define NEXTHDR_ROUTING		43	/* Routing header. */
#define NEXTHDR_FRAGMENT	44	/* Fragmentation/reassembly header. */
#define NEXTHDR_AUTH		51	/* Authentication header. */
#define NEXTHDR_ICMP		58	/* ICMP for IPv6. */
#define NEXTHDR_NONE		59	/* No next header */
#define NEXTHDR_DEST		60	/* Destination options header. */

#define DIS_XOR(n) (((n >> 24) & 0xff) ^ ((n >> 16) & 0xff) \
					^ ((n >> 8) & 0xff) ^  (n & 0xff))

#define IP_CE		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF
//#define IP_OFFMASK	0x1FF


//#define MAX_IPID_ITEM	(1<<20) // 1048576
#define MAX_IPID_ITEM	(1<<12)
#define MAX_IPID_BUFF	10240

#define isfragment(x)	((x) & (IP_MF|IP_OFFMASK))
#define	is_last_fragment(x)	((((x) & IP_MF) == 0) && ((x) & IP_OFFMASK))


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


enum dispatcher_packet_type
{
	NON_IP_PACKET,
	BARE_IP_PACKET,
	PPPOE_IP_PACKET,
	MPLS_IP_PACKET,
	ARP_PACKET,
	ETH_P_802_2_LLC_PACKET,
	IPV6_IP_PACKET,
	//you can add more type here
};

struct dispatch_vlanhdr
{
	u_int16_t vh_pri_cfi_vlan;
	u_int16_t vh_proto;
};

struct ip_frag_data
{
	u_int8_t timer;
	int8_t core_num;
	u_int8_t frag_num;
	int8_t inuse;
	int idx;
	int key;
	struct list_head pkt_list; // buffer of ip fragment
};

struct raw_pkt_node
{
	struct list_head list;
	int idx;	// dispatcher 传递给dt的索引
	int raw_packet_len;
	int8_t inuse;
	int8_t nic_num;	// 提取包的网口的序号
	//unsigned char raw_packet[RAW_PKT_NODE_LEN];
	struct nm_skb *skb;
};

struct dis_five_tuple
{
	union {
		u_int32_t ipv4_addr;
		u_int32_t ipv6_addr[4];
	} sip;
	union {
		u_int32_t ipv4_addr;
		u_int32_t ipv6_addr[4];
	} dip;
	u_int16_t sport;
	u_int16_t dport;
	u_int16_t iptype;
	u_int8_t protocol;
	u_int8_t tuple;
};

int pre_deal_pkt(u_int8_t *raw_packet, int raw_packet_len);

#endif /* _DISP_PACKET_H */
