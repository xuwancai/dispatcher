#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdio.h>

#ifdef DEBUG_ON
#define DEBUG_ERR(...) \
	do { \
		fprintf(stderr, "[%s:%s:%d]: \n", __FILE__, __FUNCTION__, __LINE__); \
		fprintf(stderr, __VA_ARGS__); \
	}while(0)
#define DEBUG_INFO(...) \
	do { \
		fprintf(stdout, "[%s:%s:%d]: \n", __FILE__, __FUNCTION__, __LINE__); \
		fprintf(stdout, __VA_ARGS__); \
	}while(0)

#else
#define DEBUG_ERR(...)
#define DEBUG_INFO(...)
#endif

#ifdef MSG_ON
#define MSG_ERR(...) DEBUG_ERR(__VA_ARGS__)
#define MSG_INFO(...) DEBUG_INFO(__VA_ARGS__)
#else
#define MSG_ERR(...)
#define MSG_INFO(...)
#endif

#endif
