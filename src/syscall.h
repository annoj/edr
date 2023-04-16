#ifndef __SYSCALL_H_
#define __SYSCALL_H_

struct syscall_enter_event {
        unsigned int pid;
        long int id;
        unsigned long int args[6];
};

void *trace_syscall(void *exiting);

#endif
