#include "edr.h"
#include "proc.h"
#include "proc.skel.h"

#include <bpf/libbpf.h>
#include <hiredis/hiredis.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

static redisContext *redis_ctx = NULL;
static struct store_event {
    time_t t;
    char cmdline[MAX_CMDLINE_LEN];
    struct event *event;
} *event;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

// store_event() uses global struct store_event *event and redisContext *redis_ctx
void store_event(void)
{
    size_t query_sz = 0xffff;
    char query[query_sz];
    redisReply *reply;

    snprintf(query, query_sz,
            "MERGE (p:Process {pid: %d}) "
            "CREATE (p)-[:HAS_CHILD_PROCESS]->(:Process {"
                "pid: %d, "
                "tgid: %d, "
                "ts: %ld, "
                "loginuid: %d, "
                "uid: %d, "
                "gid: %d, "
                "sessionid: %d, "
                "comm: '%s', "
                "cmdline: '%s', "
                "filename: '%s'"
            "})",
            event->event->ppid, event->event->tgid, event->event->pid,
            (long int)event->t, event->event->loginuid, event->event->uid,
            event->event->gid, event->event->sessionid, event->event->comm,
            event->cmdline, event->event->filename);

    reply = redisCommand(redis_ctx, "GRAPH.QUERY %s %s", REDIS_DATABASE, query);

    if (!reply) {
        fprintf(stderr, "Could not store event, no reply from redis\n");
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        fprintf(stderr, "Could not store event, error: %s\n", reply->str);
    }
}

void string_replace(char *string, size_t len, char substituent, char substitute)
{
	for (size_t i = 0; i < len - 1; i++) {
		if (string[i] == substituent) {
			string[i] = substitute;
		}
	}
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    time(&event->t);
    event->event = (struct event*)data;
    memcpy(event->cmdline, event->event->cmdline, event->event->cmdline_len);
    string_replace(event->cmdline, event->event->cmdline_len, '\0', ' ');

    // store_event() uses global struct store_event *event and redisContext *redis_ctx
    store_event();
}

void cleanup_bpf_proc(struct proc_bpf *skel, struct perf_buffer *pb)
{
    perf_buffer__free(pb);
    proc_bpf__destroy(skel);
}

int init_bpf_proc(struct proc_bpf **skel, struct perf_buffer **pb)
{
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    *skel = proc_bpf__open();
    if (!*skel) {
        fprintf(stderr, "Failed to open BPF skeleton.\n");
        return 1;
    }

    err = proc_bpf__load(*skel);
    if (err) {
        fprintf(stderr, "Failed to attach to BPF skeleton.\n");
        goto out;
    }

    err = proc_bpf__attach(*skel);
    if (err) {
        fprintf(stderr, "Failed to attach to BPF skeleton.\n");
        goto out;
    }

    *pb = perf_buffer__new(bpf_map__fd((*skel)->maps.pb),
                          8 /* 8 pages (32 KB) per CPU */,
                          handle_event, NULL, NULL, NULL);
    if (libbpf_get_error(*pb)) {
        err = 1;
        fprintf(stderr, "Failed to create buffer.\n");
    }

out:
    if (err) {
        cleanup_bpf_proc(*skel, *pb);
    }

    return err;
}

int poll_bpf_proc(struct perf_buffer *pb, volatile bool *exiting)
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

void *trace_proc(void *status)
{
    struct perf_buffer *pb = NULL;
    struct proc_bpf *skel = NULL;
    int err = 0;

    err = init_bpf_proc(&skel, &pb);
    if (err) {
        goto cleanup;
    }

    redis_ctx = redisConnect(REDIS_HOST, REDIS_PORT);
    if (redis_ctx->err) {
        fprintf(stderr, "Error initializing redis context: %s\n", redis_ctx->errstr);
        err = redis_ctx->err;
        goto cleanup;
    }

    event = malloc(sizeof(*event));
    if (!event) {
        err = errno;
        fprintf(stderr, "Error allocating memory for event: %s\n", strerror(err));
        goto cleanup;
    }

    err = poll_bpf_proc(pb, &((struct status *)status)->exiting);

cleanup:
    redisFree(redis_ctx);
    cleanup_bpf_proc(skel, pb);

    ((struct status *)status)->proc_result = err;
    ((struct status *)status)->exiting = true;

    return NULL;
}
