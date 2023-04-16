#include "edr.h"
#include "file.h"
#include "proc.h"
#include "tcp.h"
#include "syscall.h"

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct status status = {.exiting = false};

pthread_t proc;
pthread_t tcp;
pthread_t file;
pthread_t sys;

void handle_exit_signal(int signal)
{
        printf("Received %s, exiting\n", strsignal(signal));
        status.exiting = true;
        pthread_join(proc, NULL);
        pthread_join(tcp, NULL);
        pthread_join(file, NULL);
        pthread_join(sys, NULL);
}

int main(int argc, char **argv)
{
        status.exiting = false;

        signal(SIGINT, handle_exit_signal);
        signal(SIGTERM, handle_exit_signal);

        int err = pthread_create(&proc, NULL, trace_proc, (void *)&status);
        if (err) {
                fprintf(stderr, "Could not create proc thread, %s\n",
                        strerror(err));
        }

        err = pthread_create(&tcp, NULL, trace_tcp, (void *)&status);
        if (err) {
                fprintf(stderr, "Could not create tcp thread, %s\n",
                        strerror(err));
        }

        err = pthread_create(&file, NULL, trace_file, (void *)&status);
        if (err) {
                fprintf(stderr, "Could not create file thread, %s\n",
                        strerror(err));
        }

        err = pthread_create(&sys, NULL, trace_syscall, (void *)&status);
        if (err) {
                fprintf(stderr, "Could not create file thread, %s\n",
                        strerror(err));
        }

        while (!status.exiting) {
                sleep(1);
        }

        pthread_join(proc, NULL);
        pthread_join(tcp, NULL);
        pthread_join(file, NULL);
        pthread_join(sys, NULL);

        return 1;
}
