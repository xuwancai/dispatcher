#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <ucontext.h>
#include <time.h>
#include <dlfcn.h>
#include <execinfo.h>

extern unsigned long linux_syms_addresses[] __attribute__((weak, section("data")));
extern unsigned long linux_syms_num __attribute__((weak, section("data")));
extern unsigned char linux_syms_names[] __attribute__((weak, section("data")));

static const char *const siglist[] = {
	"Signal 0",
	"SIGHUP",
	"SIGINT",
	"SIGQUIT",
	"SIGILL",
	"SIGTRAP",
	"SIGABRT/SIGIOT",
	"SIGBUS",
	"SIGFPE",
	"SIGKILL",
	"SIGUSR1",
	"SIGSEGV",
	"SIGUSR2",
	"SIGPIPE",
	"SIGALRM",
	"SIGTERM",
	"SIGSTKFLT",
	"SIGCHLD",
	"SIGCONT",
	"SIGSTOP",
	"SIGTSTP",
	"SIGTTIN",
	"SIGTTOU",
	"SIGURG",
	"SIGXCPU",
	"SIGXFSZ",
	"SIGVTALRM",
	"SIGPROF",
	"SIGWINCH",
	"SIGIO",
	"SIGPOLL",
	NULL
};

static unsigned long rte_get_func_index(unsigned long addr)
{
	unsigned long low, high, mid;
	if((addr<linux_syms_addresses[0])||(addr>linux_syms_addresses[linux_syms_num-1])){
		return 0;
	}
	low=0;
	high=linux_syms_num;
	while(high-low>1){
		mid=(low+high)/2;
		if(linux_syms_addresses[mid]<=addr)
			low = mid;
		else
			high = mid;
	}
	if((low==0)||((linux_syms_num-1)==low)){
		return 0;
	}

	return low;
}

static unsigned char *rte_get_dlname(unsigned long epc, unsigned long *base)
{
	int ret;
	Dl_info info;

	ret =dladdr((void *)epc, &info);
	if(ret){
		*base = (unsigned long)info.dli_fbase;
		return (unsigned char *)info.dli_fname;
	}
	return NULL;
}

static unsigned char *rte_get_func_name(unsigned long idx)
{
	unsigned char *tmp = NULL;
	unsigned char len = 0;
	unsigned int i=0;
	tmp = linux_syms_names;
	len = *tmp;
	tmp++;
	for(i=0;i<idx;i++){
		tmp += len;
		len = *tmp;
		tmp++;
	}
	return tmp;
}

static unsigned long get_addr_from_string(char *str)
{
	unsigned long addr=0;
	char *tmp=str;	
	unsigned char val=0;
	int start=0;
	while(*tmp != ']'){
		if(start==0){
			if((*tmp=='[')&&(*(tmp+1)=='0')&&(*(tmp+2)=='x')){
				start = 1;
				tmp = tmp+2;
			}
		}else{
			val = *tmp;
			if((val>='0')&&(val<='9')){
				val = val - '0';
			}else if((val>='a')&&(val<='f')){
				val = val - 'a' + 10;
			}
			addr <<= 4;
			addr |= val;
		}
		tmp++;
	}
	return addr;
}


#define BACKTRACE_BUFF_LEN 2048
static void disp_show_backtrace(ucontext_t *ucp, int sig)
{
	unsigned char *func_name = NULL;
	unsigned long epc;
	unsigned long func_index=0;
	unsigned long dl_base=0;
	unsigned long func_addr=0;
	int start_flag = 0;
	void *bt[32];
	int bt_size;
	char **bt_sym;
	int i;
	char buff[BACKTRACE_BUFF_LEN];
	char *tmp_buff = buff;
	int fd;
	// int coreid = rte_get_self_id();
	time_t now;
	// struct tm *tm=NULL;	
	struct tm tm;
	struct timeval tv;
	struct timezone tz;	

	mcontext_t *context=NULL;;		

	memset(buff, 0, BACKTRACE_BUFF_LEN*sizeof(char));

	time(&now);
	gettimeofday(&tv, &tz);
	now += tz.tz_minuteswest * 60;
	// tm = gmtime(&now);	
	gmtime_r(&now, &tm);
	context = &(ucp->uc_mcontext);
	epc = context->gregs[REG_RIP];
	if(sig!=SIGUSR2){
		tmp_buff += sprintf(tmp_buff, "[%d-%d-%d %d:%d:%d] dispatcher exception for %s(%d)\n", 
					tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, 
					siglist[sig], sig);
		tmp_buff += sprintf(tmp_buff, "RIP:%16lx EFL:%16lx ERR:%16lx TRAPNO:%16lx\n", 
				(unsigned long)context->gregs[REG_RIP], (unsigned long)context->gregs[REG_EFL], 
				(unsigned long)context->gregs[REG_ERR], (unsigned long)context->gregs[REG_TRAPNO]);
		tmp_buff += sprintf(tmp_buff, "RAX:%16lx RBX:%16lx RCX:%16lx RDX:%16lx\n", 
				(unsigned long)context->gregs[REG_RAX], (unsigned long)context->gregs[REG_RBX],
				(unsigned long)context->gregs[REG_RCX], (unsigned long)context->gregs[REG_RDX]);
		tmp_buff += sprintf(tmp_buff, "RSI:%16lx RDI:%16lx RSP:%16lx RBP:%16lx\n", 
				(unsigned long)context->gregs[REG_RSI], (unsigned long)context->gregs[REG_RDI],
				(unsigned long)context->gregs[REG_RSP], (unsigned long)context->gregs[REG_RBP]);
		tmp_buff += sprintf(tmp_buff, "R8 :%16lx R9 :%16lx R10:%16lx R11:%16lx\n", 
				(unsigned long)context->gregs[REG_R8], (unsigned long)context->gregs[REG_R9],
				(unsigned long)context->gregs[REG_R10], (unsigned long)context->gregs[REG_R11]);
		tmp_buff += sprintf(tmp_buff, "R12:%16lx R13:%16lx R14:%16lx R15:%16lx\n", 
				(unsigned long)context->gregs[REG_R12], (unsigned long)context->gregs[REG_R13],
				(unsigned long)context->gregs[REG_R14], (unsigned long)context->gregs[REG_R15]);
		tmp_buff += sprintf(tmp_buff, "CSGSFS:%16lx\n", (unsigned long)context->gregs[REG_CSGSFS]);
	}
	
	tmp_buff += sprintf(tmp_buff, "Backtrace:\n");
	bt_size = backtrace(bt, 32);
	bt_sym = backtrace_symbols(bt, bt_size);

	for(i=0;i<bt_size;i++){ 
		func_addr = get_addr_from_string(bt_sym[i]);			
		if(func_addr == epc){ // Skip sigsem_exec etc.
			start_flag = 1;
		}
		if(start_flag){
			func_index = rte_get_func_index(func_addr);
			if(0==func_index){
				func_name = rte_get_dlname(epc, &dl_base);
				tmp_buff += sprintf(tmp_buff, "\t[<0x%lx>] %s\n", epc-dl_base, func_name);
			} else{
				func_name = rte_get_func_name(func_index);
				tmp_buff += sprintf(tmp_buff, "\t[<0x%lx>] %s\n", func_addr, func_name);
			}
		}
	}

	if(start_flag==0){
		func_index = rte_get_func_index(epc);
		if(0==func_index){
			func_name = rte_get_dlname(epc, &dl_base);
			tmp_buff += sprintf(tmp_buff, "\t[<0x%lx>] %s\n", dl_base, func_name);
		} else{
			func_name = rte_get_func_name(func_index);
			tmp_buff += sprintf(tmp_buff, "\t[<0x%lx>] %s\n", epc, func_name);
		}
	}
	free(bt_sym);

	// tb_debug_out("%s", buff);
	printf("%s", buff);

	if(sig!=SIGUSR2)
	{
    	 fd = open( "/mnt/boot/exception.txt", O_WRONLY|O_APPEND|O_CREAT, 0644);
		 if(fd<0){
		 	return;
		 }
    	 write(fd,buff,strlen(buff));
     	 close(fd);
	}
	return;
}

static void disp_record_reboot(int sig)
{
	int fd = 0;	
	char buff[512];
	char *tmp_buff = buff;
	time_t now;
	// struct tm *tm=NULL;	
	struct tm tm;
	struct timeval tv;
	struct timezone tz;	

	memset(buff, 0, 512*sizeof(char));

    fd = open( "/mnt/boot/exception.txt", O_WRONLY|O_APPEND|O_CREAT, 0644);
	if(fd<0){
		return;
	}

	time(&now);
	gettimeofday(&tv, &tz);
	now += tz.tz_minuteswest * 60;
	// tm = gmtime(&now);	
	gmtime_r(&now, &tm);
	tmp_buff += sprintf(tmp_buff, "[%d-%d-%d %d:%d:%d] dispather exception %s(%d) will reboot the system.\n", 
					tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, 
					siglist[sig], sig);

	write(fd, buff, strlen(buff));
	close(fd);
	sync();

	execlp("reboot", "reboot", NULL);

	return;
}

#if 0
static void sigsem_int(int sig, siginfo_t *sig_info, void *uc)
{
	// tb_debug_out("ZOL on core %d, call statck for SIGINT:\n", rte_get_self_id());		
	printf("dispatcher call statck for SIGINT:\n");		
	sig = sig;
	sig_info = sig_info;
	if(uc){
		disp_show_backtrace((ucontext_t *)uc, sig);
	}

#if 0
	if(global_mcb->zol_process_info.err_reboot){
		rte_record_reboot(sig);
	}
#endif
	disp_record_reboot(sig);
	return;
}
#endif

static void sigsem_exec(int sig, siginfo_t *sig_info, void *uc)
{
	struct sigaction sa;
	sig_info = sig_info;
	if(uc){
		disp_show_backtrace((ucontext_t *)uc, sig);
	}
	if(sig == SIGUSR2){
		return;
	}
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(sig, &sa, NULL);
	raise(sig);
#if 0
	if(global_mcb->zol_process_info.err_reboot){
		rte_record_reboot(sig);
	}
#endif
	disp_record_reboot(sig);
}

static void sigsem_child(int sig, siginfo_t *sig_info, void *uc)
{
	pid_t pid;
	int status;
	int fd;
	time_t now;
	// struct tm *tm=NULL;
	struct tm tm;
	struct timeval tv;
	struct timezone tz;
	char buff[BACKTRACE_BUFF_LEN];
	char *tmp_buff = buff;

	memset(buff, 0, BACKTRACE_BUFF_LEN*sizeof(char));
	time(&now);
	gettimeofday(&tv, &tz);
	now += tz.tz_minuteswest * 60;
	// tm = gmtime(&now);
	gmtime_r(&now, &tm);
	while((pid=waitpid(-1, &status, WNOHANG))>0){
    	fd = open( "/mnt/boot/exception.txt", O_WRONLY|O_APPEND|O_CREAT, 0644);
		if(fd<0){
			return;
		}
		tmp_buff += sprintf(tmp_buff, "[%d-%d-%d %d:%d:%d] dispatcher child %d terminated by ", 
					tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, pid);		
		if(WIFEXITED(status)){
			tmp_buff += sprintf(tmp_buff, "exit(%d).\n", WEXITSTATUS(status));
		}else if(WIFSIGNALED(status)){
			tmp_buff += sprintf(tmp_buff, "Signal %d.\n", WTERMSIG(status));
		}
		printf("%s", buff);
		write(fd, buff, strlen(buff));
		close(fd);
	}
	
	return;
}

static void *signal_set(int sig, void (*func)(int, siginfo_t *, void *))
{
	int ret;
	struct sigaction action;
	struct sigaction old;
	action.sa_sigaction = func;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART | SA_SIGINFO;
	ret = sigaction(sig, &action, &old);
	if(ret<0){
		return SIG_ERR;
	}else{
		return old.sa_handler;
	}
}


void disp_backtrace_init(void)
{
//	signal_set(SIGINT, sigsem_int);	
	signal_set(SIGSEGV, sigsem_exec);
	// signal_set(SIGPIPE, sigsem_exec);
	signal(SIGPIPE, SIG_IGN);
	signal_set(SIGBUS, sigsem_exec);
	signal_set(SIGILL,sigsem_exec);
	signal_set(SIGFPE, sigsem_exec);
	signal_set(SIGABRT, sigsem_exec);
	signal_set(SIGUSR2, sigsem_exec);
	signal_set(SIGCHLD, sigsem_child);
}


