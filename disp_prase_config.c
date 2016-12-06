#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <inttypes.h>

#include "libxml/xmlmemory.h"
#include "libxml/parser.h"

#include "disp_prase_config.h"

//dispatcher_conf.xml node
#define XML_ROOT             "Root"
#define XML_DISPATCHER       "Dispatcher"
#define XML_ITEM             "Item"

struct dispatcher_conf *dc = NULL;

static int32_t open_xml_file(xmlDocPtr *doc, char *xml_file_path)
{
	*doc = xmlParseFile((const char *)xml_file_path);

	if (NULL == *doc)
		return -1;
		
	return 0;
}

static int32_t move_to_dst_node(xmlDocPtr *doc, xmlNodePtr *cur, char *dst)
{
	xmlNodePtr node = NULL;
	node = xmlDocGetRootElement(*doc);

	if (NULL == node) {
		goto err;
	}

	if (xmlStrcmp(node->name, (const xmlChar *)XML_ROOT)) {
		goto err;
	}

	node = node->xmlChildrenNode;
	while (NULL != node) {
		if ((!xmlStrcmp(node->name, (const xmlChar *)dst))) {
			*cur = node->xmlChildrenNode;
			return 0;
		}
		node = node->next;
	}

err:
	return -1;
}

static int get_child_node_by_name(xmlNodePtr *cur, xmlNodePtr *child, char *name)
{
    xmlNodePtr node = *cur;

    while (NULL != node) {
        if ((!xmlStrcmp(node->name, (const xmlChar *)name))) {
            *child = node->xmlChildrenNode;
            return 0;
        }
        node = node->next;
   }

   return -1;
}

static xmlChar* get_content_by_name(xmlNodePtr *cur, char *name)
{
	xmlNodePtr node = *cur;
	xmlChar *value;

	while (NULL != node) {
		if ((!xmlStrcmp(node->name, (const xmlChar *)name))) {
			value = xmlNodeGetContent(node);
			return value;
		}
		node = node->next;
	}

	return NULL;
}


static int prase_strsplit(char* buf, char split, uint32_t* store)
{
	int num = 0;
	int data = 0;

	while (*buf != '\0') {
       if (*buf == split) {
          *(store + num++) = data;
          data = 0;
       } else {
	       data = data * 10 + *buf - '0';
	   }
       buf++;
	}
	
	*(store + num++) = data;
	
	return num;
}

/*
 * prase_dispatcher_conf: init the global var dc via xml file
 * file: the xml file with full path
 * return: 0:successed, -1: failed
 */
int prase_dispatcher_conf(char *file)
{
	xmlDocPtr doc;
	xmlNodePtr node, tmpnode;
	xmlChar *value = NULL;
	struct dispatcher_item *dispatcher_item;
	struct phy_port_item *phy_port_item;
	
	dc = (struct dispatcher_conf *)malloc(sizeof(struct dispatcher_conf));
	if (dc == NULL) {
		fprintf(stderr, "prase dispacther_conf failed! not enough memory!\n");
		return -1;
	}
	memset(dc, 0, sizeof(struct dispatcher_conf));

	if (open_xml_file(&doc, file)) {
		return -1;
	}

	if (move_to_dst_node(&doc, &node, XML_DISPATCHER)){
		xmlFreeDoc(doc);
		return -1;
	}

	value = get_content_by_name(&node, "MasterAffinity");
	if (NULL == value) 
		goto err;
	dc->master_affinity = atoi((char *)value);
	xmlFree(value);

	value = get_content_by_name(&node, "NTuple");
	if (NULL == value) 
		goto err;
	dc->n_tuple = atoi((char *)value);
	xmlFree(value);

	value = get_content_by_name(&node, "AppNum");
	if (NULL == value) 
		goto err;
	dc->app_num = atoi((char *)value);
	xmlFree(value);

	value = get_content_by_name(&node, "DispatcherNum");
	if (NULL == value) 
		goto err;
	dc->dispatcher_num = atoi((char *)value);
	xmlFree(value);
    if (dc->dispatcher_num > MAX_DISPATCHER_NUM)
	    goto err;

	if (!get_child_node_by_name(&node, &tmpnode, "DispatcherItem")) {
		while (NULL != tmpnode) {
            if (xmlStrcmp(tmpnode->name, (const xmlChar *)XML_ITEM)) {
                tmpnode = tmpnode->next;
                continue;
            }
                
			value = get_content_by_name(&tmpnode->xmlChildrenNode, "DispatcherItemID");
            dispatcher_item = dc->dispatcher_item + atoi((char *)value);
            dispatcher_item->item_id = atoi((char *)value);
            xmlFree(value);
			
			value = get_content_by_name(&tmpnode->xmlChildrenNode, "AffinityCore");
            dispatcher_item->affinity_core = atoi((char *)value);
            xmlFree(value);

			value = get_content_by_name(&tmpnode->xmlChildrenNode, "PhysicalPortNum");
            dispatcher_item->phy_port_num = atoi((char *)value);
            xmlFree(value);

			value = get_content_by_name(&tmpnode->xmlChildrenNode, "PhysicalPortID");
			if (prase_strsplit((char*)value, ',', dispatcher_item->phy_port_id) != 
				dispatcher_item->phy_port_num)
				goto err;
            xmlFree(value);
            
			tmpnode = tmpnode->next;
		}
	}
	
	value = get_content_by_name(&node, "PhysicalPortNum");
	if (NULL == value) 
		goto err;
	dc->phy_port_num = atoi((char *)value);
	xmlFree(value);
    if (dc->phy_port_num > RTE_MAX_ETHPORTS)
	    goto err;

	if (!get_child_node_by_name(&node, &tmpnode, "PhysicalPortItem")) {
		while (NULL != tmpnode) {
            if (xmlStrcmp(tmpnode->name, (const xmlChar *)XML_ITEM)) {
                tmpnode = tmpnode->next;
                continue;
            }
            
			value = get_content_by_name(&tmpnode->xmlChildrenNode, "PhysicalPortID");
            phy_port_item = dc->phy_port_item + atoi((char *)value);
            xmlFree(value);
			
			value = get_content_by_name(&tmpnode->xmlChildrenNode, "RxQueneNum");
            phy_port_item->rx_queue_num = atoi((char *)value);
            xmlFree(value);

			value = get_content_by_name(&tmpnode->xmlChildrenNode, "TxQueneNum");
            phy_port_item->tx_queue_num = atoi((char *)value);
            xmlFree(value);

			value = get_content_by_name(&tmpnode->xmlChildrenNode, "BufferNum");
            phy_port_item->buf_num = atoi((char *)value);
            xmlFree(value);

			value = get_content_by_name(&tmpnode->xmlChildrenNode, "BufferLen");
            phy_port_item->buf_len = atoi((char *)value);
            xmlFree(value);
            
			tmpnode = tmpnode->next;
		}
	}

	xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
	
err:
	xmlFreeDoc(doc);
	xmlCleanupParser();
	fprintf(stderr, "prase dispacther conf failed!\n");
	return -1;
}

/*
 * clean_dispatcher_conf: free dc
 */
void clean_dispatcher_conf(void)
{
	free(dc);
	return;
}
