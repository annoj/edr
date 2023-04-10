#ifndef __PROC_H_
#define __PROC_H_

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512
#define MAX_COMMANDLINE_LEN 2048

struct event {
	unsigned int pid;
	unsigned int ppid;
	unsigned int uid;
	unsigned int gid;
	unsigned int loginuid;
	unsigned int sessionid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	char commandline[MAX_COMMANDLINE_LEN];
	unsigned int commandline_len;
};

void *trace_proc(void *exiting);

#endif