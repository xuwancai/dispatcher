#ifndef _CAPTOR_H
#define _CAPTOR_H

#include <sys/types.h>

#define CAPTOR_ARG_NUM	32
#define RAW_PACKET_LEN	2000
#define CAPTOR_NAME_LEN	64
#define INVALID_CAPTOR_HANDLE (unsigned long)(-1)

typedef unsigned long captor_handle_t;
typedef captor_handle_t (*captor_open_t)(int argc, char **argv);
typedef int (*captor_capture_t)(captor_handle_t handler, u_int8_t **pkt_buf_p,
		unsigned long *pkt_container);
typedef int (*captor_send_t)(captor_handle_t handler, unsigned long *pkt_container, int dst);
typedef void (*captor_close_t)(captor_handle_t handler);
typedef void *(*captor_getbase_t)(captor_handle_t handler);
typedef void *(*captor_mmap_t)(captor_handle_t handler);
typedef int (*captor_munmap_t)(void *address);
typedef void (*captor_cleanctl_t)(u_int8_t *pkt_buf_p);

typedef struct captor_struct
{
	char				name[CAPTOR_NAME_LEN];
	captor_open_t		open;
	captor_close_t		close;
	captor_capture_t	capture;
	captor_send_t		send;
	captor_getbase_t	getbase;
	captor_mmap_t		mmap;
	captor_munmap_t 	munmap;
	captor_cleanctl_t	cleanctl;
}captor_t;

#if 0
typedef struct captor_desc
{
	captor_t *captor;
	int handler;
}captor_desc_t;
#define CAPTOR_DESC_NUM	8
#endif

int InitCaptor(void);
void CleanCaptor(void);
captor_t *SearchCaptor(char *captor_name);
int OpenCaptor(char *captor_name, int argc, char *argv[]);
int CaptorCapture(int capid, u_int8_t **pkt_buf_p, unsigned long *pkt_container);
int CaptorSend(int capid, unsigned long *pkt_container, int dst);
void CaptorCleanCtl(int capid, u_int8_t *pkt_buf_p);
void CloseCaptor(int capid);

#endif
