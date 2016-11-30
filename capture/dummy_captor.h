#ifndef _DUMMY_CAPTOR_H
#define _DUMMY_CAPTOR_H

#include <sys/types.h>
#include "capture/captor.h"

captor_handle_t dummy_captor_open(int argc, char *argv[]);
int dummy_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_t, unsigned long *pkt_container);
void dummy_captor_close(captor_handle_t hdlr);

extern captor_t dummy_captor;

#endif
