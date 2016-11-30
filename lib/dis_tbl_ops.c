#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

#include "disp_tbl_ops.h"
#include "hash.h"

//#define DIS_MSG_FILE "/tmp/.dis_msg"
int dis_client_fd = 0;
pthread_rwlock_t dtlock;
/*
 * 进程(线程)启动时初始化一次即可
 */
int dt_msg_lock_init(void)
{
	pthread_rwlock_init(&dtlock, NULL);
	return 0;
}

void dt_msg_lock_destory(void)
{
	pthread_rwlock_destroy(&dtlock);
	return;
}

int dis_client_un_stream_init(void)
{
	int ret;
	int len;
	struct sockaddr_un addr;
	struct stat s_stat;
	uid_t euid;
	char *path = DIS_MSG_FILE;

	/* Stat socket to see if we have permission to access it. */
	euid = geteuid();
	ret = stat (path, &s_stat);
	if (ret < 0 && errno != ENOENT)
	{
		fprintf(stderr, "connect(%s): stat = %s\n", path, strerror(errno)); 
		return -1;
	}

	if (ret >= 0)
	{
#ifdef S_ISSOCK
		if (! S_ISSOCK(s_stat.st_mode))
		{
			fprintf(stderr, "connect(%s): Not a socket\n",  path);
			return -1;
		}
#endif
		if (euid != s_stat.st_uid 
				|| !(s_stat.st_mode & S_IWUSR)
				|| !(s_stat.st_mode & S_IRUSR))
		{
			fprintf(stderr, "connect(%s): No permission to access socket\n", path);
			return -1;
		}
	}

	dis_client_fd= socket (AF_UNIX, SOCK_STREAM, 0);
	if (dis_client_fd < 0)
	{
		fprintf(stderr, "connect(%s): error is :%s\n", path, strerror(errno));
		return -1;
	}

	memset (&addr, 0, sizeof (struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy (addr.sun_path, path, strlen (path));
#ifdef HAVE_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof (addr.sun_family) + strlen (addr.sun_path);
#endif /* HAVE_SUN_LEN */

	ret = connect (dis_client_fd, (struct sockaddr *) &addr, len);
	if (ret < 0)
	{
		fprintf(stderr, "connect(%s): error is: %s\n", path, strerror(errno));
		close (dis_client_fd);
		return -1;
	}
	dt_msg_lock_init();

	return 0;
}

static int send_msg_to_disp(int m_type, key_args_t *karg)
{
	dis_msg_buff_t msg;

	if (dis_client_fd <=0)
		return -1;
	memset(&msg, 0, sizeof(msg));
	msg.mtype = DIS_CMD_TYPE;
	msg.msg_type = m_type;
	msg.key = karg->key;
	msg.core_num = karg->core_id;
	memcpy(&(msg.karg), karg, sizeof(msg.karg));
	
	pthread_rwlock_wrlock(&dtlock);
	if(write(dis_client_fd, &msg, sizeof(msg)) < 0)
	{
		//close(dis_mqid);
		return -2;
	}
	pthread_rwlock_unlock(&dtlock);


	while (1)
	{
		int nbytes;

		pthread_rwlock_rdlock(&dtlock);
		nbytes = read (dis_client_fd, &msg, sizeof(msg));
		pthread_rwlock_unlock(&dtlock);

		if (nbytes <= 0 && errno != EINTR)
		{
			return -3;
		}

		if (nbytes > 0)
		{
			if (msg.msg_type == DIS_CMD_TYPE_CHILD_ADD_SUCCESS
				|| msg.msg_type == DIS_CMD_TYPE_CHILD_REMOVE_SUCCESS
				|| msg.msg_type == DIS_CMD_TYPE_SET_DEBUG_SUCCESS)
				break;
			else if (msg.msg_type == DIS_CMD_TYPE_CHILD_ADD_UNSUCCESS
				|| msg.msg_type == DIS_CMD_TYPE_CHILD_REMOVE_UNSUCCESS)
				return -4;
		}
	}

	return 0;
}

int dis_client_un_stream_clean(void)
{
	close(dis_client_fd);
	dt_msg_lock_destory();
	return 0;
}

int dis_add_child_table(key_args_t *arg)
{
	arg->key = 0;
	arg->mask = 0;
	if(arg->sip != 0)
	{
		arg->key += arg->sip;
		arg->mask |= KEY_SIP;
	}
	if(arg->dip != 0)
	{
		arg->key += arg->dip;
		arg->mask |= KEY_DIP;
	}
	if(arg->sport != 0)
	{
		arg->key += arg->sport;
		arg->mask |= KEY_SPORT;
	}
	if(arg->dport != 0)
	{
		arg->key += arg->dport;
		arg->mask |= KEY_DPORT;
	}
	if(arg->protocol != 0)
	{
		arg->key += arg->protocol;
		arg->mask |= KEY_PROTOCOL;
	}
	return send_msg_to_disp(DIS_CMD_TYPE_CHILD_ADD, arg);
}

int dis_remove_child_table(key_args_t *arg)
{
	arg->key = 0;
	arg->mask = 0;
	if(arg->sip != 0)
	{
		arg->key += arg->sip;
		arg->mask |= KEY_SIP;
	}
	if(arg->dip != 0)
	{
		arg->key += arg->dip;
		arg->mask |= KEY_DIP;
	}
	if(arg->sport != 0)
	{
		arg->key += arg->sport;
		arg->mask |= KEY_SPORT;
	}
	if(arg->dport != 0)
	{
		arg->key += arg->dport;
		arg->mask |= KEY_DPORT;
	}
	if(arg->protocol != 0)
	{
		arg->key += arg->protocol;
		arg->mask |= KEY_PROTOCOL;
	}
	return send_msg_to_disp(DIS_CMD_TYPE_CHILD_REMOVE, arg);
}

int dis_set_debug(key_args_t *arg)
{
	return send_msg_to_disp(DIS_CMD_TYPE_SET_DEBUG, arg);
}

