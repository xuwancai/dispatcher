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
#include "rte_log.h"
#include "rte_malloc.h"
#include "rte_memory.h"
#include "rte_memcpy.h"
#include "rte_memzone.h"
#include "rte_eal.h"
#include "rte_per_lcore.h"
#include "rte_launch.h"
#include "rte_atomic.h"
#include "rte_cycles.h"
#include "rte_prefetch.h"
#include "rte_lcore.h"
#include "rte_per_lcore.h"
#include "rte_branch_prediction.h"
#include "rte_interrupts.h"
#include "rte_random.h"
#include "rte_debug.h"
#include "rte_ether.h"
#include "rte_ethdev.h"
#include "rte_mempool.h"
#include "rte_mbuf.h"

#include "disp_common.h"
#include "dispatcher.h"

struct rte_dispatcher *rte_dispatcher = NULL;

struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];
struct rte_mempool *pktmbuf_pool = NULL;

static const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static rte_atomic32_t thread_init_cnt = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t thread_exit_cnt = RTE_ATOMIC32_INIT(0);

int do_cleanup = 0;
int global_serial_no = 0;

#if 0
int packet_callback(struct nm_pkt_header *nph)
{
	int ret_worker_id = 0;

	if((unsigned int)nph->len < sizeof(struct ethhdr))
	{
		goto err;
	}

	ret_worker_id = pre_deal_pkt(nph->pkt, nph->len, nph);
	if((ret_worker_id < 1) || (ret_worker_id > dc->app_num))
	{
		goto err;
	}
	nph->o_ifindex = (ret_worker_id - 1) * dc->thread_num + nph->tidx + 1;
	//nph->o_ifindex += nph->tidx * 4;
	if (0 == nm_send_pkt(nph)) {
		//(dp->send_ok_packet[ret_worker_id - 1])++;
	}

	return 0;
err:
	return -1;
}
#endif

static int detect_process(char * process_name)
{
	FILE *ptr;
	char buff[64] = {0};
	char ps[64];
	sprintf(ps,"ps | grep -c %s", process_name);
	if((ptr = popen(ps, "r")) != NULL)
	{
		while (fgets(buff, sizeof(buff), ptr) != NULL)
		{
			if(atoi(buff) >= 2)
			{
				pclose(ptr);
				return 0;
			}
		}
	}else
		return -1;
	pclose(ptr);
	return -1;
}

static void hup(int signo)
{
	//print_dispatcher_profile();
	return;
}

static void report_msg(int signo)
{
	//print_dispatcher_profile();
	return;
}

//for signal()
static void setcleanup(int sig)
{
	do_cleanup = 1;
	return;
}

//for set_signal()
static void set_cleanup(int signo, siginfo_t *sig, void *data)
{
	do_cleanup = 1;
	return;
}

static void clean_interface(void)
{
    uint32_t portid;
	for (portid = 0; portid < dc->phy_port_num; portid++) {
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	
	return;
}

static void clean_global(void)
{
	rte_free(rte_dispatcher);
	clean_interface();
	clean_dispatcher_conf();
	
	return;
}

static void signal_init(void)
{
	//setsignal(SIGTERM, set_cleanup);
	//setsignal(SIGINT, set_cleanup);
	signal(SIGTERM, setcleanup);
	signal(SIGINT, setcleanup);
	//signal(SIGSEGV, core_dump);
	signal(SIGHUP, hup);
	signal(50, report_msg);	
	
	disp_backtrace_init();

	return;
}

static int init_dispatcher(void)
{
    int i;
    int ret;
    
    rte_dispatcher = rte_zmalloc(DISPATCHER_NAME, sizeof(*rte_dispatcher) * dc->dispatcher_num, RTE_CACHE_LINE_SIZE);
    if (rte_dispatcher == NULL) {
        printf("init_dispatcher: rte_zmalloc error!\n");
        return -1;
    }
        
    for (i = 0; i < dc->dispatcher_num; i++) {
        memcpy((void*)&(rte_dispatcher[i].disp_item), (void*)(dc->dispatcher_item + i), sizeof(dc->dispatcher_item[i]));
    }
    
	signal_init();

	if (init_child_ssn()){
	    printf("init_dispatcher: init_child_ssn error!\n");
        return -1;
	}
	
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status(uint8_t port_num)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status: ");
	fflush(stdout);
	
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						"Mbps - %s\n", (uint8_t)portid,
						(unsigned)link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("finish\n");
		}
	}

	return;
}

static int init_interface(void) 
{
	int ret;
	int i;
    int portid;
	struct phy_port_item *phy_port_item;
	struct rte_eth_dev_info dev_info;

	/* create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("dispatcher_mbuf_pool", 8192,
							MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
							rte_socket_id());
	if (pktmbuf_pool == NULL) {
		printf("Cannot init mbuf pool\n");
		return -1;
	}

	/* Initialise each port */
	for (portid = 0; portid < dc->phy_port_num; portid++) {
        phy_port_item = dc->phy_port_item + portid;

        rte_eth_dev_info_get(portid, &dev_info);
        
		/* init port */
		printf("Initializing port %u... ", (unsigned) portid);	
		fflush(stdout);
		
		ret = rte_eth_dev_configure(portid, phy_port_item->rx_queue_num, 
									phy_port_item->tx_queue_num, &port_conf);
		if (ret < 0) {
			printf("Cannot configure device: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}

        rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
        
		ret = rte_eth_rx_queue_setup(portid, 0, DIPATCHER_RX_DESC_DEFAULT,
					     rte_eth_dev_socket_id(portid), NULL, pktmbuf_pool);
		if (ret < 0) {
			printf("rte_eth_rx_queue_setup: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}

		ret = rte_eth_tx_queue_setup(portid, 0, DIPATCHER_TX_DESC_DEFAULT,
					rte_eth_dev_socket_id(portid), NULL);
		if (ret < 0) {
			printf("rte_eth_tx_queue_setup: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}

		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			printf("rte_eth_dev_start: err=%d, port=%u\n",
					ret, (unsigned) portid);
			return -1;
		}
		printf("done: \n");

        printf("mac: ");
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            if (i == ETHER_ADDR_LEN-1)
               printf("0x%02x", ports_eth_addr[portid].addr_bytes[i]);
            else
               printf("0x%02x:", ports_eth_addr[portid].addr_bytes[i]);
        }
        printf("\n");
        
		rte_eth_promiscuous_enable(portid);	
	}

	check_all_ports_link_status(dc->phy_port_num);
	
	return 0;
}

static void packet_handle(struct rte_dispatcher *local_dispatcher)
{
    uint32_t i;

    uint32_t portid;
    uint32_t nb_rx;
    uint32_t rx_index;
    uint32_t nb_tx;
    uint32_t work_id;
    uint32_t inqueue;
    static uint32_t total_rx = 0;
    static uint32_t total_tx = 0;
    static uint64_t total_last = 0;
    
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	
	for (i = 0; i < local_dispatcher->disp_item.phy_port_num; i++) {

		portid = local_dispatcher->disp_item.phy_port_id[i];
		nb_rx = rte_eth_rx_burst((uint8_t) portid, 0, pkts_burst, MAX_PKT_BURST);
        if (nb_rx != 0) {
            total_rx += nb_rx;
            for (rx_index = 0; rx_index < nb_rx; rx_index++) {
                work_id = pre_deal_pkt(rte_pktmbuf_mtod(pkts_burst[rx_index], u_int8_t *),
                                       rte_pktmbuf_pkt_len(pkts_burst[rx_index]));

                inqueue = rte_ring_enqueue(local_dispatcher->app_ring[work_id-1], pkts_burst[rx_index]);
                if (inqueue != 1) {
                    printf("rte_ring_enqueue error!\n");
                }
            }
            nb_tx = rte_eth_tx_burst((uint8_t) portid, 0, pkts_burst, nb_rx);
            total_tx += nb_tx;
        }
	}

    if (total_rx - total_last > 1000) {
        total_last = total_rx;
        printf("packet info: portid = %d, rx = %d, tx = %d\n", portid, total_rx, total_tx);
    }

	return;
}

/* 初始化dispatcher与app main的队列 */
static int init_queue(struct rte_dispatcher *local_dispatcher)
{
    int i;
    int ret;
    struct rte_ring *ring;
 	char ring_name[32];
 	
    /* 创建dispatcher 与app main的报文队列 */
    for (i = 0; i < dc->app_num; i++) {
    	ret = snprintf(ring_name, sizeof(ring_name), "disp%d:app-main%d", 
    	               local_dispatcher->disp_item.item_id, i);
	    if (ret < 0 || ret >= (int)sizeof(ring_name)) {
	        printf("creater ring name error %d\n", i);
            return -1;
        }
        
        ring = rte_ring_create(ring_name, MAX_RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (ring == NULL) {
            printf("creater ring queue error %s\n", ring_name);
            return -1;
        }
        local_dispatcher->app_ring[i] = ring;
    }
    
    return 0;
}

static void * dispatcher_main(void *arg)
{
	int ret;
	struct rte_dispatcher *local_dispatcher = (struct rte_dispatcher *)arg;
	
	rte_thread_init_slave(local_dispatcher->disp_item.affinity_core);

    /* 创建dispatcher 与app main的报文队列 */
    if (init_queue(local_dispatcher))
        exit(0);
    
	/* read on our pipe to get commands */
    rte_atomic32_inc(&thread_init_cnt);
    while (rte_atomic32_read(&thread_init_cnt) != dc->dispatcher_num) {
       rte_pause();
    }
     
	/* 最后一个线程写入 */
	if (local_dispatcher->disp_item.item_id == (dc->dispatcher_num - 1)) {
		ret = system("echo 1 > /tmp/dispatcher.ok");
		if (WIFSIGNALED(ret) && (WTERMSIG(ret)==SIGINT || WTERMSIG(ret)==SIGQUIT)) {
			printf("Can not create file /tmp/disptcher.ok!\n");
		}
	}

    #if 0
	do { /*waiting for app_main to initialize the share memory */
		sleep(1);
		//printf("Pid %d, waiting...\n", getpid());
	} while (-1 == detect_process("vtysh"));
    #endif
    
	while(1) {
		if (unlikely(do_cleanup)) {
		    rte_atomic32_inc(&thread_exit_cnt);
			exit(0);
		}
	    packet_handle(local_dispatcher);
	}
	
	exit(0);
}

int main(int argc, char *argv[])
{
    int i;
	int ret;
	int core_id;
	char thread_name[RTE_MAX_THREAD_NAME_LEN];
	
	if (argc > 1) {
		global_serial_no = atoi(argv[1]);
	}

	ret = system("echo 0 > /tmp/dispatcher.ok");
	if (WIFSIGNALED(ret) && 
		(WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT)) {
		printf("Can not create file /tmp/disptcher.ok!\n");
	    exit(0); /* don't run dispatcher on ATOM platform */
	}
	
	if (sysconf(_SC_NPROCESSORS_ONLN) < 3) {
		ret = system("echo 1 > /tmp/dispatcher.ok");
		if (WIFSIGNALED(ret) && 
			(WTERMSIG(ret) == SIGINT || WTERMSIG(ret) == SIGQUIT)) {
			printf("Can not create file /tmp/disptcher.ok!\n");
		}
		exit(0); /* don't run dispatcher on ATOM platform */
	}

	if (prase_dispatcher_conf((char*)"dispatcher.xml")) 
		return -1;
		
	if (rte_eal_init_custom(dc->master_affinity))
		goto err;

	if (init_dispatcher())
		goto err;

	if (init_interface())
		goto err;

    for (i = 0; i < dc->dispatcher_num; i++) {
		core_id = dc->dispatcher_item[i].affinity_core;
		ret = pthread_create(&lcore_config[core_id].thread_id, NULL,
						     dispatcher_main, rte_dispatcher + i);
		if (ret != 0) {
			printf("Cannot create thread\n");
			goto err;
		}
			
		snprintf(thread_name, RTE_MAX_THREAD_NAME_LEN, "dispatcher%d", i);
		ret = rte_thread_setname(lcore_config[core_id].thread_id, thread_name);
		if (ret != 0)
			printf("Cannot set name for lcore thread\n");
	}
				
    while (1) {
  		sleep(1);
        if (rte_atomic32_read(&thread_exit_cnt) == dc->dispatcher_num)
            break;
    }
    
	clean_global();
	return 0;
err:
	return -1;
}
