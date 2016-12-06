#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "disp_common.h"
#include "hash.h"
#include "dispatcher.h"

extern struct hash_t *child_table[];
extern struct disp_cb *disp_cb;

static inline int _hash_key2idx(hkey_t key, int tablelen)
{
	return (key < (hkey_t)tablelen ? key : (key % (hkey_t)tablelen));
}

static inline int dis_ipv6_addr_equal(u_int32_t *a1, u_int32_t *a2)
{
	return (((a1[0] ^ a2[0]) | (a1[1] ^ a2[1]) | (a1[2] ^ a2[2])
				|(a1[3] ^ a2[3])) == 0);
}
int hash_equal_func(struct hashitem_t *ht, key_args_t *args)
{
	key_args_t *karg = &(ht->karg);
	unsigned short match_type = args->match_type;
	if(match_type == 3){
		if (args->iptype == 4) {
			if((karg->sip.ipv4_addr == args->sip.ipv4_addr)
					&& (karg->dip.ipv4_addr == args->dip.ipv4_addr)
					&& (karg->dport == args->dport)){
				return 1;
			}
			if((karg->sip.ipv4_addr == args->dip.ipv4_addr)
					&& (karg->dip.ipv4_addr == args->sip.ipv4_addr)
					&& (karg->dport == args->sport)){
				return 1;
			}
		}
	}else if(match_type == 5){
		if (args->iptype == 4) {
			if((karg->sip.ipv4_addr == args->sip.ipv4_addr)
					&& (karg->dip.ipv4_addr == args->dip.ipv4_addr)
					&& (karg->sport == args->sport) && (karg->dport == args->dport)
					&& (karg->protocol == args->protocol)){
				return 1;
			}
			if((karg->sip.ipv4_addr == args->dip.ipv4_addr)
					&& (karg->dip.ipv4_addr == args->sip.ipv4_addr)
					&& (karg->sport == args->dport) && (karg->dport == args->sport)
					&& (karg->protocol == args->protocol)){
				return 1;
			}
		} else {
			if ((dis_ipv6_addr_equal(karg->sip.ipv6_addr, args->sip.ipv6_addr))
					&& (dis_ipv6_addr_equal(karg->dip.ipv6_addr, args->dip.ipv6_addr))
					&& (karg->sport == args->sport) && (karg->dport == args->dport)
					&& (karg->protocol == args->protocol)) {
				return 1;
			}
			if ((dis_ipv6_addr_equal(karg->sip.ipv6_addr, args->dip.ipv6_addr))
					&& (dis_ipv6_addr_equal(karg->dip.ipv6_addr, args->sip.ipv6_addr))
					&& (karg->sport == args->dport) && (karg->dport == args->sport)
					&& (karg->protocol == args->protocol)) {
				return 1;
			}
		}
	}
	return 0;
}

static inline struct hashitem_t *_hash_get_node(hkey_t key, struct htnode_t *table_node, 
		hash_equal_func_t h_eqfunc, key_args_t *hash_equal_arg)
{
	struct hashitem_t *item = NULL;

	//这里用reverse，主要是考虑到最后插入的数据
	list_for_each_entry_reverse(item, &(table_node->conflict_head), conflict_node) {
		if(item->ht_key == key){
			if(h_eqfunc == NULL){
				return item;
			}else if(h_eqfunc(item, hash_equal_arg)>0){
				return item;
			}
		}
	}

	return NULL;
}

int get_coreid_from_hash(key_args_t *karg)
{
	unsigned int key = karg->key;		
	unsigned int h_idx = 0;	
	struct htnode_t *table_node = NULL;
	struct hashitem_t *item = NULL;
	struct child_node *data = NULL;
	int core_id = -1;
	hash_equal_func_t h_eqfunc = NULL;	
	int node_id = rte_socket_id();

	/*unsigned short match_type = karg->match_type;*/
	if((disp_cb==NULL)||(disp_cb->init_ok==0)){
		return -1;
	}

#ifdef HANDLE_CONFLICT_ON
	h_eqfunc = hash_equal_func;	
#endif

	h_idx = _hash_key2idx(key, child_table[node_id]->h_table_num);
	table_node = child_table[node_id]->h_table + h_idx;	

	rte_rwlock_read_unlock(&table_node->htnode_lock);
	if(table_node->conflict_num == 0){
		rte_rwlock_read_unlock(&table_node->htnode_lock);
		return -1;
	}
	item = _hash_get_node(key, table_node, h_eqfunc, karg);
	if (NULL != item) {
		data = hash_item_entry(item, struct child_node, hash_node);
		core_id = data->core_num;
	}
	rte_rwlock_read_unlock(&table_node->htnode_lock);

	return core_id;
}
