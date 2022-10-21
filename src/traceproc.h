#ifndef __TRACEPROC_H
#define __TRACEPROC_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

struct event {
	int pid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif