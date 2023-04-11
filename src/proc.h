#ifndef __PROC_H_
#define __PROC_H_

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512
#define MAX_CMDLINE_LEN 2048

struct proc_exec_event {
	unsigned int pid;
	unsigned int ppid;
    unsigned int tgid;
	unsigned int uid;
	unsigned int gid;
	unsigned int loginuid;
	unsigned int sessionid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	char cmdline[MAX_CMDLINE_LEN];
	unsigned int cmdline_len;
};

void *trace_proc(void *exiting);

#endif