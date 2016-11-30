#include <stdio.h>

#include "cap_file_captor.h"

#define MAX_CAP_FILENAME_LEN 256
#define CAPFILE_SHM_SIZE	(4096*4096)
#define CAPFILE_SHM_KEY		0x20121113

static u_int8_t *shm_buf = NULL;
static int shm_id = -1;

static int init_shm(void);
static void clean_shm(void);
static void *cap_file_captor_getbase(captor_handle_t hdlr);
static int cap_file_captor_munmap(void *address);
void *cap_file_captor_mmap(captor_handle_t hdlr);

captor_t cap_file_captor = 
{
	.name = "cap_file",
	.open = cap_file_captor_open,
	.close = cap_file_captor_close,
	.capture = cap_file_captor_capture,
	.mmap = cap_file_captor_mmap,
	.munmap = cap_file_captor_munmap,
	.getbase = cap_file_captor_getbase,
};

captor_handle_t cap_file_captor_open(int argc, char *argv[])
{
	return 0;
}

int cap_file_captor_capture(captor_handle_t hdlr, u_int8_t **pkt_buf_p, unsigned long pkt_container)
{
	return 0;
}

void cap_file_captor_close(captor_handle_t hdlr)
{
	return;
}

void *cap_file_captor_getbase(captor_handle_t hdlr)
{
	return NULL;
}

void *cap_file_captor_mmap(captor_handle_t hdlr)
{
	return NULL;
}

int cap_file_captor_munmap(void *address)
{
	return 0;
}

int init_shm(void)
{
	return 0;
}

void clean_shm(void)
{
	return;
}
