#ifndef _DISPA_PRASE_CONFIG_H
#define _DISPA_PRASE_CONFIG_H

#include "rte_config.h"

#define DESPATCHER_CONF_FILE  "/usr/local/etc/dispatcher_conf.xml"
#define MAX_DISPATCHER_NUM    10

struct dispatcher_item 
{
    uint32_t item_id;
	uint32_t affinity_core;
	uint32_t phy_port_num;
	uint32_t phy_port_id[RTE_MAX_ETHPORTS];
};

struct phy_port_item 
{    
	uint32_t rx_queue_num;
	uint32_t tx_queue_num;
	uint32_t buf_num;
	uint32_t buf_len;
};

struct dispatcher_conf
{
	int master_affinity;
	int n_tuple;
	int app_num;

	int dispatcher_num;
	struct dispatcher_item dispatcher_item[MAX_DISPATCHER_NUM];

	int phy_port_num;
	struct phy_port_item phy_port_item[RTE_MAX_ETHPORTS];
};

extern struct dispatcher_conf *dc;

int prase_dispatcher_conf(char *file);
void clean_dispatcher_conf(void);

#endif /* _DISPA_PRASE_CONFIG_H */

