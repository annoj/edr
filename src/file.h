#ifndef __FILE_H_
#define __FILE_H_

#define MAX_FILE_FILENAME_LEN 2048

struct file_open_event {
        unsigned int pid;
        char filename[MAX_FILE_FILENAME_LEN];
        unsigned int flags;
        unsigned int mode;
};

void *trace_file(void *exiting);

#endif
