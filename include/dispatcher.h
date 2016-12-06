#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include <stdio.h>
#include <sys/types.h>

#include "disp_prase_config.h"
#include "disp_packet.h"

#define DIPATCHER_RX_DESC_DEFAULT   128
#define DIPATCHER_TX_DESC_DEFAULT   512
#define MEMPOOL_CACHE_SIZE          256
#define MAX_PKT_BURST               16
#define MAX_RING_SIZE               8192
#define MAX_APP_MAIN                32
#define DISPATCHER_NAME             "dispatcher"

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
