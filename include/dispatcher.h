#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include <stdio.h>
#include <sys/types.h>

#include "userspace_list.h"
#include "hash.h"
#include "disp_prase_config.h"
#include "disp_packet.h"

#define DIPATCHER_RX_DESC_DEFAULT   128
#define DIPATCHER_TX_DESC_DEFAULT   512
#define MEMPOOL_CACHE_SIZE          256
#define MAX_PKT_BURST               16

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


#define MAX_RING_SIZE       8192

#define DISPATCHER_NAME     "dispatcher"
#define MAX_APP_MAIN        32

struct rte_dispatcher {
    struct dispatcher_item disp_item;
    struct rte_ring *app_ring[MAX_APP_MAIN];
}__rte_cache_aligned;


struct disp_cb{
	unsigned int debug_flag;
	char init_ok;
	char need_lock;
};

// for child ssn
struct child_node
{
	struct hashitem_t hash_node;
	int8_t core_num; // 需要分拨的核编号
	int8_t del_flag; // 标记删除
	u_int8_t timer;
};

int child_table_check(struct dis_five_tuple *t);

#if 0
int child_table_init(void);
struct hash_t *child_table_get(void);
int add_child_table(struct hash_t *child_table, key_args_t *arg);
int reset_child_table(void);
void child_table_clean(void);
#endif

void disp_backtrace_init(void);

#endif
