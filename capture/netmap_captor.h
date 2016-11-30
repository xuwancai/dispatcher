#ifndef _NETMAP_CAPTOR_H
#define _NETMPA_CAPTOR_H

#include <sys/types.h>
#include "capture/captor.h"

captor_handle_t netmap_captor_open(int argc, char *argv[]);
int netmap_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_p, unsigned long *pkt_container);
int netmap_captor_send(captor_handle_t hdlr, unsigned long *pkt_container, int dst);
void netmap_captor_close(captor_handle_t hdlr);
extern captor_t netmap_captor;
#endif /* _NETMAP_CAPTOR_H */
