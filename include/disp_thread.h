#ifndef _DIS_THREAD_H
#define _DIS_THREAD_H

#include <sys/types.h>
#include <pthread.h>

typedef struct THREAD_ARGS
{
	pthread_t tid;
	pid_t tpid;
	int tidx;
	int status;
}thread_args_t;

typedef struct THREAD_PRIV_DATA
{
	pthread_attr_t *attr; 
	pthread_t *msg_thread;
	thread_args_t *thread_args; 
	thread_args_t *msg_thread_arg;
}thread_priv_t;

int init_thread_args(int num, thread_args_t **args);
int init_thread_attr(int num, pthread_attr_t **attr);

#endif
