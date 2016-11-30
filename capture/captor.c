#include <stdio.h>
#include "../include/capture/captor.h"
#include "dummy_captor.h"
//#include "cap_file_captor.h"
#include "netmap_captor.h"

#define CAPTOR_DESC_NUM 8
typedef struct captor_desc
{
	captor_t *captor;
	int handler;
}captor_desc_t;

static captor_desc_t captor_desc_table[CAPTOR_DESC_NUM];
static int captor_desc_size = 0;

static captor_t *captors[] =
{
	&dummy_captor,
//	&cap_file_captor,
	&netmap_captor,
	NULL
};

int InitCaptor(void)
{
	int i;
	for(i=0; i<CAPTOR_DESC_NUM; i++)
	{
		captor_desc_table[i].captor = NULL;
		captor_desc_table[i].handler = -1;
	}
	captor_desc_table[0].captor = &dummy_captor;
	captor_desc_table[0].handler = 0;
	captor_desc_size = 1;
	return 0;
}

/*
 * SearchCaptor
 */
captor_t *SearchCaptor(char *captor_name)
{
	captor_t **cap = NULL;
	for(cap = captors; *cap != NULL; cap++)
	{
		if( strcasecmp((*cap)->name, captor_name) == 0 ) break;
	}
	return *cap;
}

int OpenCaptor(char *captor_name, int argc, char *argv[])
{
	int index = 0;
	if(captor_name == NULL || captor_name[0] == 0) goto err;
	if(captor_desc_size == CAPTOR_DESC_NUM) goto err;
	index = captor_desc_size;
	if((captor_desc_table[index].captor = SearchCaptor(captor_name)) == NULL)
	{
		fprintf(stderr, "Error: OpenCaptor can't find captor(%s)!\n", captor_name);
		goto err;
	}
	captor_desc_table[index].handler = ((captor_desc_table[index].captor)->open)(argc, argv);
	if(captor_desc_table[index].handler < 0)
	{
		fprintf(stderr, "Error: OpenCaptor can't open captor(%s)!\n", captor_name);
		goto err;
	}
	captor_desc_size++;
	return index;
err:
	return -1;
}

int CaptorCapture(int capid, u_int8_t **pkt_buf_p, unsigned long *pkt_container)
{
	if((captor_desc_table[capid].captor)->capture)
		return ((captor_desc_table[capid].captor)->capture)(captor_desc_table[capid].handler, pkt_buf_p, pkt_container);
	return -1;
}

int CaptorSend(int capid, unsigned long *pkt_container, int dst)
{
	if ((captor_desc_table[capid].captor)->send)
		return ((captor_desc_table[capid].captor)->send)(captor_desc_table[capid].handler, pkt_container, dst);
	return -1;
}

void CaptorCleanCtl(int capid, u_int8_t *pkt_buf_p)
{
	if((captor_desc_table[capid].captor)->cleanctl)
	{
		((captor_desc_table[capid].captor)->cleanctl)(pkt_buf_p);
	}
	return;
}

void CloseCaptor(int capid)
{
	if(capid > 0)
	{
		if((captor_desc_table[capid].captor)->close)
		{
			((captor_desc_table[capid].captor)->close)(captor_desc_table[capid].handler);
		}
		else
		{
			fprintf(stderr, "Error: captor(name: %s, id: %d) didn't register a close routine!\n",
					(captor_desc_table[capid].captor)->name, capid);
		}
	}
	else
	{
		fprintf(stderr, "Error: captor id(%d) error!\n", capid);
	}
	return;
}

void CleanCaptor(void)
{
	int i = 0;
	for(i=0; i< CAPTOR_DESC_NUM; i++)
	{
		captor_desc_table[i].captor = NULL;
		captor_desc_table[i].handler = -1;
	}
	captor_desc_size = 0;
	return;
}
