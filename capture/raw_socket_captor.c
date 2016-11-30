#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>

#include "raw_socket_captor.h"

static captor_handle_t raw_socket_captor_open(int argc, char **argv);
static void raw_socket_captor_close(captor_handle_t hdlr);
static int raw_socket_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_p);
void *raw_socket_captor_mmap(captor_handle_t handler);
static int raw_socket_captor_munmap(void *address);
static void *raw_socket_captor_getbase(captor_handle_t handler);
static int init_shm(void);
static void clean_shm(void);

captor_t raw_socket_captor = 
{
	.name = "raw_socket",
	.open = raw_socket_captor_open,
	.close = raw_socket_captor_close,
	.capture = raw_socket_captor_capture,
	.mmap = raw_socket_captor_mmap,
	.munmap = raw_socket_captor_munmap,
	.getbase = raw_socket_captor_getbase,
};

#define RAW_SHM_SIZE (4096*4096)
#define RAW_SHM_KEY	 0x19861006
static u_int8_t raw_packet_space[RAW_PACKET_LEN];
#define MAX_NIC_NUMBER 32
int devfd[MAX_NIC_NUMBER];
int sockfd;

static u_int8_t *shm_buff = NULL;
static int shm_id = -1;

captor_handle_t raw_socket_captor_open(int argc, char **argv)
{
	struct ifreq ifr;
	int i;

	if(argc == 0)
	{
		fprintf(stderr, "Error: raw socket arg syntax:ifname1 [ifname2...]\n");
		goto err;
	}

	sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if(sockfd < 0)
	{
		perror("socket call");
		goto err;
	}

	for(i=0; i<MAX_NIC_NUMBER; i++)
	{
		devfd[i] = -1;
	}

	for(i=0; i<argc; i++)
	{
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, argv[i], sizeof(ifr.ifr_name) - 1);

		//get nic index
		if(ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0)
		{
			perror("ioctl SIOCGIFINDEX");
			goto err;
		}
		devfd[ifr.ifr_ifindex] = sockfd;
		//DUMP_R("NIC_INDEX: %d\n", ifr.ifr_ifindex);

		//set promisc mode
		if(ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
		{
			perror("ioctl SIOCGIFFLAGS");
			goto err;
		}
		ifr.ifr_flags |= IFF_PROMISC;
		if(ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
		{
			perror("ioctl SIOCSIFFLAGS");
			goto err;
		}
	}
	return (captor_handle_t)sockfd;

err:
	return INVALID_CAPTOR_HANDLE;
}

int raw_socket_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_p)
{
	int nread = 0;
	struct sockaddr_ll from;
	socklen_t fromlen;
	static u_int8_t *pfree = NULL;

	if(hdlr == INVALID_CAPTOR_HANDLE) goto err;

	while(1)
	{
		fromlen = sizeof(from);
		bzero(&from, fromlen);

		nread = recvfrom(hdlr, (char *)raw_packet_space, RAW_PACKET_LEN, 0, (struct sockaddr *)&from, &fromlen);
		if(nread < 0)
		{
			if(errno = EINTR) continue;
			goto err;
		}
		if(nread == 0) continue;

		//DUMP_R("NIC_INDEX: %d\n", from.sll_ifindex);

		if(devfd[from.sll_ifindex] >= 0) break; //filter
	}

	if(shm_buff == NULL)
	{
		*pkt_buf_p = raw_packet_space;
	}
	else
	{
		if(pfree == NULL) pfree = shm_buff;

		if(RAW_SHM_SIZE - (pfree - shm_buff) < nread) pfree = shm_buff;

		memcpy(pfree, raw_packet_space, nread);
		*pkt_buf_p = pfree;
		pfree += nread;
	}

	return nread;

err:
	return -1;
}

void raw_socket_captor_close(captor_handle_t hdlr)
{
	if(sockfd > 0) close(sockfd);
	clean_shm();
	return;
}

void *raw_socket_captor_getbase(captor_handle_t handler)
{
	if(shm_buff == NULL)
	{
		if(init_shm() < 0) return NULL;
	}
	return (void *)shm_buff;
}

void *raw_socket_captor_mmap(captor_handle_t handler)
{
	char *addr = NULL;
	int id = shmget(RAW_SHM_KEY, RAW_SHM_SIZE, IPC_CREAT);
	if(id < 0)
	{
		perror("raw_socket_captor_mmap shmget");
		goto err;
	}

	addr = shmat(id, 0, 0);
	if(addr == (char *)-1)
	{
		perror("raw_socket_captor_mmap shmat");
		goto err;
	}

	return (void *)addr;

err:
	return NULL;
}

int raw_socket_captor_munmap(void *address)
{
	return shmdt(address);
}

int init_shm(void)
{
	shm_buff = (u_int8_t *)malloc(sizeof(u_int8_t) * RAW_SHM_SIZE);
	if(shm_buff == NULL)
	{
		fprintf(stderr, "shm_buff malloc error[%s - %s]\n", __FILE__, __func__);
		return -1;
	}
	return 0;
}

void clean_shm(void)
{
	if(shm_buff != NULL) free(shm_buff);
}
#if 0
int init_shm(void)
{
	shm_id = shmget(RAW_SHM_KEY, RAW_SHM_SIZE, IPC_CREAT | 0x1c0);
	if(shm_id < 0)
	{
		perror("raw_socket_captor shmget");
		goto err;
	}

	shm_buff = shmat(shm_id, 0, 0);
	if(shm_buff == (u_int8_t *)-1)
	{
		perror("raw_socket_captor shmat");
		goto err;
	}
	return 0;

err:
	clean_shm();
	return -1;
}

void clean_shm(void)
{
	if(shm_buff) shmdt(shm_buff);
	if(shm_id >= 0) shmctl(shm_id, IPC_RMID, 0);
	shm_id = -1;
	shm_buff = NULL;
	return;
}
#endif
