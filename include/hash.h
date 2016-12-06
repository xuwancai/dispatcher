#ifndef _HASH_H
#define _HASH_H

#include <pthread.h>
#include <sys/types.h>

#include "userspace_list.h"
// #include "atomic.h"
// #include "disp_tbl_ops.h"
#include "rte_eal.h"
#include "rte_atomic.h"
#include "rte_rwlock.h"

#define HANDLE_CONFLICT_ON

//key��unsigned int����Ϊ������ip����
typedef unsigned int hkey_t;

typedef struct _key_args
{
	unsigned int key;
	union {
		u_int32_t ipv4_addr;
		u_int32_t ipv6_addr[4];
	} sip;
	union {
		u_int32_t ipv4_addr;
		u_int32_t ipv6_addr[4];
	} dip;
	unsigned short sport;
	unsigned short dport;
	unsigned char protocol;
	unsigned short match_type;
	unsigned short iptype;
	int core_id;
}key_args_t;

struct htnode_t
{
	struct list_head conflict_head; // hashͰ��ͷ
	// pthread_rwlock_t htnode_lock;	// hashͰ����
	rte_rwlock_t htnode_lock;
	unsigned int conflict_num;	// ��ͻ����
};

// data node
struct hashitem_t
{
	struct list_head conflict_node; // hashͰ������ڵ�
	struct htnode_t *table_item;	// back to htable, for quick delete
	key_args_t karg; 		//��ͻ���ʱ�õ��Ĳ���
	hkey_t ht_key;

	rte_atomic32_t reference; 	// ���ü�������ֹ��ʹ��ʱ��ɾ����reference==0ʱ����ʾ��Ҫɾ���ýڵ�
	unsigned int size;		// ��ʶ��ǰ�ڵ��С
};

struct hash_t
{
	struct htnode_t *h_table;	// table head
	int h_table_num;
	rte_atomic32_t h_items;		// ԭ�Ӳ���
	int max_item;	// ��������
};

typedef int (*hash_equal_func_t)(struct hashitem_t *data_ht, key_args_t *arg);
#define hash_item_entry(ptr, type, member)	container_of(ptr, type, member)

int hash_equal_func(struct hashitem_t *data_ht, key_args_t *arg);

int get_coreid_from_hash(key_args_t *karg);

#endif // _HASH_H
