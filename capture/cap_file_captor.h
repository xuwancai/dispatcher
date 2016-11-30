#ifndef _CAP_FILE_CAPTOR_H
#define _CAP_FILE_CAPTOR_H

#include <sys/types.h>
#include "capture/captor.h"

captor_handle_t cap_file_captor_open(int argc, char *argv[]);
int cap_file_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_p, unsigned long pkt_container);
void cap_file_captor_close(captor_handle_t hdlr);

extern captor_t cap_file_captor;

#endif
