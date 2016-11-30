#ifndef _DIS_TBL_OPS_H
#define _DIS_TBL_OPS_H

#define DIS_MSG_FILE "/tmp/.dis_msg"

#define DIS_CMD_TYPE    100

#define DIS_CMD_TYPE_CHILD_MIN      0
#define DIS_CMD_TYPE_CHILD_ADD      1
#define DIS_CMD_TYPE_CHILD_REMOVE   2
#define DIS_CMD_TYPE_SET_DEBUG   3
#define DIS_CMD_TYPE_CHILD_ADD_SUCCESS 50
#define DIS_CMD_TYPE_CHILD_ADD_UNSUCCESS 51
#define DIS_CMD_TYPE_CHILD_REMOVE_SUCCESS 52
#define DIS_CMD_TYPE_CHILD_REMOVE_UNSUCCESS 53

#define DIS_CMD_TYPE_SET_DEBUG_SUCCESS 60

typedef struct _key_args
{
	unsigned int key;
	unsigned int sip;
	unsigned int dip;
	unsigned short sport;
	unsigned short dport;
	unsigned char protocol;
	unsigned short mask;
	int core_id;
}key_args_t;

typedef struct _dis_msg_buff
{
	long mtype;
	unsigned int key;
	int core_num;
	int msg_type;
	key_args_t karg;
}dis_msg_buff_t;

int dis_client_un_stream_init(void);
int dis_client_un_stream_clean(void);
int dis_add_child_table(key_args_t *arg);
int dis_remove_child_table(key_args_t *arg);
int dis_set_debug(key_args_t *arg);
#endif
