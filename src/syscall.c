#include "syscall.h"
#include "edr.h"
#include "syscall-table.h"
#include "syscall.skel.h"

#include <bpf/libbpf.h>
#include <hiredis/hiredis.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static const char **syscalls;
static redisContext *redis_ctx = NULL;
static struct store_syscall_event {
        time_t t;
        const char *syscall_name;
        struct syscall_enter_event *event;
} *event;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
        return vfprintf(stderr, format, args);
}

// store_event() uses global struct store_event *event and redisContext
// *redis_ctx
static void store_event(void)
{
        size_t query_sz = 0xffff;
        char query[query_sz];
        redisReply *reply;

        snprintf(query, query_sz,
                 "MERGE (p:Process {pid: %u}) "
                 "CREATE (p)-[:SYSCALL]->(:SyscallEnter {"
                         "id: %lu, "
                         "syscall_name: '%s' ,"
                         "args0: '0x%lx', "
                         "args1: '0x%lx', "
                         "args2: '0x%lx', "
                         "args3: '0x%lx', "
                         "args4: '0x%lx', "
                         "args5: '0x%lx'"
                 "})",
                 event->event->pid, event->event->id, event->syscall_name,
                 event->event->args[0], event->event->args[1],
                 event->event->args[2], event->event->args[3],
                 event->event->args[4], event->event->args[5]);

        reply =
            redisCommand(redis_ctx, "GRAPH.QUERY %s %s", REDIS_DATABASE, query);

        if (!reply) {
                fprintf(stderr, "Could not store event, no reply from redis\n");
        }

        if (reply->type == REDIS_REPLY_ERROR) {
                fprintf(stderr, "Could not store event, error: %s\n",
                        reply->str);
        }
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
        time(&event->t);
        event->event = (struct syscall_enter_event *)data;

        event->syscall_name = syscall_table[event->event->id];

        // store_event() uses global struct store_event *event and redisContext
        // *redis_ctx
        store_event();
}

static void cleanup_bpf_syscall(struct syscall_bpf *skel,
                                struct perf_buffer *pb)
{
        perf_buffer__free(pb);
        syscall_bpf__destroy(skel);
}

static int init_bpf_syscall(struct syscall_bpf **skel, struct perf_buffer **pb)
{
        int err;

        libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
        libbpf_set_print(libbpf_print_fn);

        *skel = syscall_bpf__open();
        if (!*skel) {
                fprintf(stderr, "Failed to open BPF skeleton.\n");
                return 1;
        }

        err = syscall_bpf__load(*skel);
        if (err) {
                fprintf(stderr, "Failed to attach to BPF skeleton.\n");
                goto out;
        }

        err = syscall_bpf__attach(*skel);
        if (err) {
                fprintf(stderr, "Failed to attach to BPF skeleton.\n");
                goto out;
        }

        *pb = perf_buffer__new(bpf_map__fd((*skel)->maps.pb),
                               8 /* 8 pages (32 KB) per CPU */, handle_event,
                               NULL, NULL, NULL);
        if (libbpf_get_error(*pb)) {
                err = 1;
                fprintf(stderr, "Failed to create buffer.\n");
        }

out:
        if (err) {
                cleanup_bpf_syscall(*skel, *pb);
        }

        return err;
}

static int poll_bpf_syscall(struct perf_buffer *pb, volatile bool *exiting)
{
        int err = 0;

        while (!*exiting) {
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

        return err;
}

void *trace_syscall(void *status)
{
        struct perf_buffer *pb = NULL;
        struct syscall_bpf *skel = NULL;
        int err = 0;

        syscalls = init_syscall_table();

        err = init_bpf_syscall(&skel, &pb);
        if (err) {
                goto cleanup;
        }

        redis_ctx = redisConnect(REDIS_HOST, REDIS_PORT);
        if (redis_ctx->err) {
                fprintf(stderr, "Error initializing redis context: %s\n",
                        redis_ctx->errstr);
                err = redis_ctx->err;
                goto cleanup;
        }

        event = malloc(sizeof(*event));
        if (!event) {
                err = errno;
                fprintf(stderr, "Error allocating memory for event: %s\n",
                        strerror(err));
                goto cleanup;
        }

        err = poll_bpf_syscall(pb, &((struct status *)status)->exiting);

cleanup:
        redisFree(redis_ctx);
        cleanup_bpf_syscall(skel, pb);

        ((struct status *)status)->syscall_result = err;
        ((struct status *)status)->exiting = true;

        return NULL;
}
