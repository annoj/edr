#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "traceproc.skel.h"
#include "traceproc.h"

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
    printf("Exiting.\n");
    exiting = true;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    const struct event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    printf("%-8s %-5s %-7d %-16s %s\n", 
           ts, "EXEC", e->pid, e->comm, e->filename);
}

int main(int argc, char **argv)
{
    struct perf_buffer *pb = NULL;
    struct traceproc_bpf *skel;
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = traceproc_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton.\n");
        return 1;
    }

    err = traceproc_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to attach to BPF skeleton.\n");
        goto cleanup;
    }

    err = traceproc_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach to BPF skeleton.\n");
        goto cleanup;
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.pb),
                          8 /* 8 pages (32 KB) per CPU */,
                          handle_event, NULL, NULL, NULL);
    if (libbpf_get_error(pb)) {
        err = -1;
        fprintf(stderr, "Failed to create buffer.\n");
        goto cleanup;
    }

    printf("%-8s %-5s %-7s %-16s %s\n",
           "TIME", "EVENT", "PID", "COMM", "FILENAME");
    while (!exiting) {
        err = perf_buffer__poll(pb, 100 /* timeout in ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }

        if (err < 0) {
            printf("Error polling perf buffer: %d.\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    traceproc_bpf__destroy(skel);
    
    return err < 0 ? -err : 0;
}