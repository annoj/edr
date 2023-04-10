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

redisContext *redis_ctx = NULL;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

int store_event(const struct event *e, time_t t, redisContext *ctx)
{
    size_t query_sz = 0xffff;
    char query[query_sz];
    redisReply *reply;

    snprintf(query, query_sz,
            "MERGE (p:Process {pid: %d}) "
            "CREATE (p)-[:HAS_CHILD_PROCESS]->(:Process {"
                "pid: %d, "
                "ts: %ld, "
                "loginuid: %d, "
                "uid: %d, "
                "gid: %d, "
                "sessionid: %d, "
                "comm: '%s', "
                "commandline: '%s', "
                "filename: '%s'"
            "})",
            e->ppid, e->pid, (long int)t, e->loginuid, e->uid, e->gid,
            e->sessionid, e->comm, e->commandline, e->filename);

    reply = redisCommand(ctx, "GRAPH.QUERY %s %s", REDIS_DATABASE, query);

    if (!reply) {
        return -1;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        fprintf(stderr, "Could not store event, error: %s\n", reply->str);
        return -1;
    }

    return 0;
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
    struct event *e;
    struct tm *tm;
    char ts[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // Copy read only event data to writable memory and replace '\0' bytes in 
    // e->commandline with ' '.
    // TODO: This seems to be quite inefficient is there a better way?
    // TODO: malloc and memcpy can fail, implement error handling.
    e = malloc(sizeof(*e));
    memcpy(e, data, sizeof(*e));
    string_replace(e->commandline, e->commandline_len, '\0', ' ');

    printf("%-8s %-5s %-7d %-7d %-9d %-7d %-7d %-10d %-16s %-64s %s\n", 
           ts, "EXEC", e->pid, e->ppid, e->loginuid, e->uid, e->gid,
           e->sessionid, e->comm, e->commandline, e->filename);

    store_event(e, t, redis_ctx);
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
        goto out;
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

    printf("%-8s %-5s %-7s %-7s %-9s %-7s %-7s %-10s %-16s %-64s %s\n",
           "TIME", "EVENT", "PID", "PPID", "LOGINUID", "UID", "GID",
           "SESSIONID", "COMM", "COMMANDLINE", "FILENAME");

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
        fprintf(stderr, "Failed to initialize redis context.\n");
        err = redis_ctx->err;
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
