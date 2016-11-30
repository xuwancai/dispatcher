#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include <stdio.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

#include "userspace_list.h"
#include "hash.h"


#define MAX_PHY_CPU_NUM 2
#define POLICY_AVERAGE	0
#define POLICY_FLOW		1
#define POLICY_IP		2

#define IP_CE		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define IP_OFFSET	0x1FFF
//#define IP_OFFMASK	0x1FFF

#define MAX_CAPTURE_CONTINUOUS_ERROR	128
#define CAPTURE_STOP	0
#define CAPTURE_ERR		-1
#define CAPTURE_NO		-2


#define CAPTOR_ARG_NUM	32
#define CAPTOR_ARGSTR_LEN	80
#define DEFAULT_CAPTOR_NAME	"dummy"
#define RUNARGS_LEN		256
#define RUNARGS_NUM		32
#define DEFAULT_RUNARGS	""


//#define MAX_IPID_ITEM	(1<<20) // 1048576
#define MAX_IPID_ITEM	(1<<12)
#define MAX_IPID_BUFF	10240

#define isfragment(x)	((x) & (IP_MF|IP_OFFMASK))
#define	is_last_fragment(x)	((((x) & IP_MF) == 0) && ((x) & IP_OFFMASK))


#define RAW_PKT_NODE_LEN 2048

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

int (*dispatch_task)(char *pkt, int len, u_int8_t *ip_head, int num);
int dispatch_task_average(char *pkt, int len, u_int8_t *ip_head, int num);
int dispatch_task_ip(char *pkt, int len, u_int8_t *ip_head, int num);


// for child ssn
struct child_node
{
	struct hashitem_t hash_node;
	int8_t core_num; // 需要分拨的核编号
	int8_t del_flag; // 标记删除
	u_int8_t timer;
};

int child_table_init(void);
struct hash_t *child_table_get(void);
int child_table_check(struct dis_five_tuple *t);
int add_child_table(struct hash_t *child_table, key_args_t *arg);
int reset_child_table(void);
void child_table_clean(void);
void disp_backtrace_init(void);

#endif
