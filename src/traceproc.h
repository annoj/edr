#ifndef __TRACEPROC_H
#define __TRACEPROC_H

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_DATABASE "EDR"

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

struct event {
	int pid;
	int ppid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	unsigned int loginuid;
	unsigned int uid;
	unsigned int gid;
	unsigned int sessionid;
};

#endif