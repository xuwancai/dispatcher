#include <stdio.h>
#include "dummy_captor.h"
//#include "capture/captor.h"

captor_t dummy_captor = 
{
	name:"dummy",
	open:dummy_captor_open,
	close:dummy_captor_close,
	capture:dummy_captor_capture,
};

captor_handle_t dummy_captor_open(int argc, char *argv[])
{
	return 0;
}

int dummy_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_t, unsigned long *pkt_container)
{
	sleep(1);
	printf("Dummy captor capture done!\n");
	return 0;
}

void dummy_captor_close(captor_handle_t hdlr)
{
	return;
}
