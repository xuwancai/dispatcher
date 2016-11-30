#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "rte_config.h"

#include "disp_common.h"
#include "hash.h"
#include "dispatcher.h"


#define MAX_CYCLE_CHILD_ALARM	2
#define MAX_TIME_CHILD_ALARM	10
#define MAX_CHILD_ITEM_SIZE		100000 /*����10����������ӱ�����ڹ�ϣ����*/

#define DISPATCHER_DEBUG_CHILD (0x1L << 4)

struct hash_t *child_table[RTE_MAX_NUMA_NODES];
struct disp_cb *disp_cb = NULL;
extern struct dispatcher_conf *dc;
unsigned int *netmap_debug_flag = NULL;

#define  NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	
#ifndef NIP6
#define NIP6_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define NIP6(addr)					\
	(unsigned)(((unsigned char *)addr)[0]),			\
	(unsigned)(((unsigned char *)addr)[1]),			\
	(unsigned)(((unsigned char *)addr)[2]),			\
	(unsigned)(((unsigned char *)addr)[3]),			\
	(unsigned)(((unsigned char *)addr)[4]),			\
	(unsigned)(((unsigned char *)addr)[5]),			\
	(unsigned)(((unsigned char *)addr)[6]),			\
	(unsigned)(((unsigned char *)addr)[7]),			\
	(unsigned)(((unsigned char *)addr)[8]),			\
	(unsigned)(((unsigned char *)addr)[9]),			\
	(unsigned)(((unsigned char *)addr)[10]),			\
	(unsigned)(((unsigned char *)addr)[11]),			\
	(unsigned)(((unsigned char *)addr)[12]),			\
	(unsigned)(((unsigned char *)addr)[13]),			\
	(unsigned)(((unsigned char *)addr)[14]),			\
	(unsigned)(((unsigned char *)addr)[15])
#endif

/* Ŀǰֻ֧��5Ԫ����ȫ����� */
int child_table_check(struct dis_five_tuple *t)
{
	unsigned int key = 0;
	int core_id = 0;
	key_args_t karg;

	//Ϊ�˼���hash��ѯ�����Ч�ʣ���������һЩ���ģ�������tcpЭ�飬�Ͷ˵ı���
	if((t->protocol != 6)&&(t->protocol != 17)&&(t->protocol != 47)) //��tcpЭ�鲻��������
		goto err;

	/*if((sport != 20 && sport < 1024)
			|| (dport != 20 && dport < 1024)) //�Ͷ˿ڲ��������ӣ�20�˿�һ����������
	{
		goto err;
	}*/

	memset(&karg, 0, sizeof(key_args_t));
#ifdef HANDLE_CONFLICT_ON
	memcpy(karg.sip.ipv6_addr, t->sip.ipv6_addr, 16);
	memcpy(karg.dip.ipv6_addr, t->dip.ipv6_addr, 16);
	karg.sport = t->sport;
	karg.dport = t->dport;
	karg.protocol = t->protocol;
	karg.iptype = t->iptype;
#endif

	if (t->iptype == 4)
		key = t->sip.ipv4_addr + t->dip.ipv4_addr + t->sport + t->dport + t->protocol;
	else
		key = t->sip.ipv6_addr[0] + t->sip.ipv6_addr[1]
				+ t->sip.ipv6_addr[2] + t->sip.ipv6_addr[3]
				+ t->dip.ipv6_addr[0] + t->dip.ipv6_addr[1]
				+ t->dip.ipv6_addr[2] + t->dip.ipv6_addr[3]
				+ t->sport + t->dport + t->protocol;
	karg.key = key;
	karg.match_type = 5;
	core_id = get_coreid_from_hash(&karg);
	if(core_id < 0){
		goto err;
	}

	if(*netmap_debug_flag & DISPATCHER_DEBUG_CHILD){
		if (t->iptype == 4)
			printf("Check :Dispatch ( %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu), coreid=%d, key=0x%x\r\n",
				NIPQUAD(t->sip.ipv4_addr), ntohs(t->sport), 
				NIPQUAD(t->dip.ipv4_addr), ntohs(t->dport), core_id, key);
		else
			printf("Check :Dispatch ("NIP6_FMT":%hu -> "NIP6_FMT":%hu), coreid=%d, key=0x%x\r\n",
				NIP6(t->sip.ipv6_addr), ntohs(t->sport),
				NIP6(t->dip.ipv6_addr), ntohs(t->dport), core_id, key);
	}
	return core_id;
	
err:
	return -1;
}
