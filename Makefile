DIR = $(shell pwd)

INCLUDE = -I./include -I/home/xuwancai/fw-dpdk/build/include 

LDFLAGS = -L/home/xuwancai/LAM_REL_APOLLO/ctrl_plane/libs/x86_64 -L/home/xuwancai/fw-dpdk/build/lib 

LDFLAGS += -ldl -lpthread -lc -lxml2 
LDFLAGS += -ldpdk
LDFLAGS += -lrte_acl
LDFLAGS += -lrte_cfgfile
LDFLAGS += -lrte_cmdline
LDFLAGS += -lrte_cryptodev
LDFLAGS += -lrte_distributor
LDFLAGS += -lrte_eal
LDFLAGS += -lrte_ethdev
LDFLAGS += -lrte_hash
LDFLAGS += -lrte_ip_frag
LDFLAGS += -lrte_jobstats
LDFLAGS += -lrte_kni
LDFLAGS += -lrte_kvargs
LDFLAGS += -lrte_lpm
LDFLAGS += -lrte_mbuf
LDFLAGS += -lrte_mempool
LDFLAGS += -lrte_meter
LDFLAGS += -lrte_net
LDFLAGS += -lrte_pdump
LDFLAGS += -lrte_pipeline
LDFLAGS += -lrte_pmd_af_packet
LDFLAGS += -lrte_pmd_bnxt
LDFLAGS += -lrte_pmd_bond
LDFLAGS += -lrte_pmd_cxgbe
LDFLAGS += -lrte_pmd_e1000
LDFLAGS += -lrte_pmd_ena
LDFLAGS += -lrte_pmd_enic
LDFLAGS += -lrte_pmd_fm10k
LDFLAGS += -lrte_pmd_i40e
LDFLAGS += -lrte_pmd_ixgbe
LDFLAGS += -lrte_pmd_null
LDFLAGS += -lrte_pmd_null_crypto
LDFLAGS += -lrte_pmd_qede
LDFLAGS += -lrte_pmd_ring
LDFLAGS += -lrte_pmd_vhost
LDFLAGS += -lrte_pmd_virtio
LDFLAGS += -lrte_pmd_vmxnet3_uio
LDFLAGS += -lrte_port
LDFLAGS += -lrte_power
LDFLAGS += -lrte_reorder
LDFLAGS += -lrte_ring
LDFLAGS += -lrte_sched
LDFLAGS += -lrte_table
LDFLAGS += -lrte_timer
LDFLAGS += -lrte_vhost

CC = gcc
CFLAGS = -g -Wall -O0 -march=native -m64 ${INCLUDE} ${LDFLAGS}

SRC = $(wildcard ${DIR}/*.c)
OBJ = $(patsubst %.c,%.o, $(notdir ${SRC})) 

TARGET = dispatcher

${TARGET}:${OBJ}
	$(CC) $(CFLAGS) $^ -o ${TARGET}

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	rm -rf ${TARGET} 
	rm -rf *.o
