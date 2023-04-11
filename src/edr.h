#ifndef __EDR_H_
#define __EDR_H_

#include <stdbool.h>

#define REDIS_HOST "localhost"
#define REDIS_PORT 6379
#define REDIS_DATABASE "EDR"

struct status {
    volatile bool exiting;
    volatile int proc_result;
    volatile int tcp_result;
    volatile int file_result;
};

#endif