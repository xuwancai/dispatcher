#include <stdio.h>
#include "nm_lib_captor.h"
#include "netmap_captor.h"

static void *netmap_captor_getbase(captor_handle_t hdlr);

captor_t netmap_captor = 
{
	.name = "netmap",
	.open = netmap_captor_open,
	.close = netmap_captor_close,
	.capture = netmap_captor_capture,
	.send = netmap_captor_send,
	.getbase = netmap_captor_getbase,
};

captor_handle_t netmap_captor_open(int argc, char *argv[])
{
	struct nm_handler *nh = NULL;

	if (argc != 3)
		goto ret;
	nm_global_init();
	
	nh = nm_init(argv[0], atoi(argv[1]), r_nic, -1, atoi(argv[2]));

ret:	
	return (captor_handle_t)nh;
}

int netmap_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_p, unsigned long *pkt_container)
{
	int ret;
	struct nm_skb *skb;
	struct nm_handler *nh = (struct nm_handler *)hdlr;
	ret = nm_recv(&skb);
	if (-1 == ret)
		return -2;
	else if (-2 == ret)
		return -1;
	else {
		*pkt_buf_p = skb->data;
		*pkt_container = (unsigned long)skb;
		return skb->len;
	}
}

int netmap_captor_send(captor_handle_t hdlr, unsigned long *pkt_container, int dst)
{
	return 0;
}

void netmap_captor_close(captor_handle_t hdlr)
{
	nm_clean();
	nm_global_clean();
	return;
}

static void *netmap_captor_getbase(captor_handle_t hdlr)
{
	return NULL;
}

