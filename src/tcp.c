#include "edr.h"
#include "tcp.h"
#include "tcp.skel.h"

#include <bpf/libbpf.h>
#include <hiredis/hiredis.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static redisContext *redis_ctx = NULL;
static struct store_tcp_event {
    time_t t;
    char saddr[16];
    char daddr[16];
    char saddr_v6[39];
    char daddr_v6[39];
    struct tcp_event *event;
} *event;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

// store_event() uses global struct store_event *event and redisContext *redis_ctx
static void store_event(void)
{
    size_t query_sz = 0xffff;
    char query[query_sz];
    redisReply *reply;

    snprintf(query, query_sz,
            "MERGE (p:Process {pid: %u}) "
            "CREATE (p)-[:HAS_TCP_CONNECTION]->(:TCPConnection {"
                "oldstate: %u, "
                "newstate: %u, "
                "sport: %u, "
                "dport: %u, "
                "saddr: '%s', "
                "daddr: '%s', "
                "saddr_v6: '%s', "
                "daddr_v6: '%s'"
            "})",
            event->event->pid, event->event->oldstate, event->event->newstate,
            event->event->sport, event->event->dport, event->saddr, event->daddr,
            event->saddr_v6, event->daddr_v6);

    reply = redisCommand(redis_ctx, "GRAPH.QUERY %s %s", REDIS_DATABASE, query);

    if (!reply) {
        fprintf(stderr, "Could not store event, no reply from redis\n");
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        fprintf(stderr, "Could not store event, error: %s\n", reply->str);
    }
}

static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    time(&event->t);
    event->event = (struct tcp_event*)data;
    event->saddr[0] = '\0';
    event->daddr[0] = '\0';
    event->saddr_v6[0] = '\0';
    event->daddr_v6[0] = '\0';
    // snprintf(event->saddr, "%d.%d.%d.%d", event->event->saddr[0],
    //          event->event->saddr[1], event->event->saddr[2],
    //          event->event->saddr[3]);
    // snprintf(event->daddr, "%d.%d.%d.%d", event->event->daddr[0],
    //          event->event->daddr[1], event->event->daddr[2],
    //          event->event->daddr[3]);
    // snprintf(event->saddr_v6, "%x:%x:%x:%x:%x:%x:%x:%x", event->event->saddr_v6[0],
    //          event->event->saddr_v6[1], event->event->saddr_v6[2], event->event->saddr_v6[3],
    //          event->event->saddr_v6[4], event->event->saddr_v6[5], event->event->saddr_v6[6],
    //          event->event->saddr_v6[7]);
    // snprintf(event->daddr_v6, "%x:%x:%x:%x:%x:%x:%x:%x", event->event->daddr_v6[0],
    //          event->event->daddr_v6[1], event->event->daddr_v6[2], event->event->daddr_v6[3],
    //          event->event->daddr_v6[4], event->event->daddr_v6[5], event->event->daddr_v6[6],
    //          event->event->daddr_v6[7]);

    // store_event() uses global struct store_event *event and redisContext *redis_ctx
    store_event();
}

static void cleanup_bpf_tcp(struct tcp_bpf *skel, struct perf_buffer *pb)
{
    perf_buffer__free(pb);
    tcp_bpf__destroy(skel);
}

static int init_bpf_tcp(struct tcp_bpf **skel, struct perf_buffer **pb)
{
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    *skel = tcp_bpf__open();
    if (!*skel) {
        fprintf(stderr, "Failed to open BPF skeleton.\n");
        return 1;
    }

    err = tcp_bpf__load(*skel);
    if (err) {
        fprintf(stderr, "Failed to attach to BPF skeleton.\n");
        goto out;
    }

    err = tcp_bpf__attach(*skel);
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
        cleanup_bpf_tcp(*skel, *pb);
    }

    return err;
}

static int poll_bpf_tcp(struct perf_buffer *pb, volatile bool *exiting)
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

void *trace_tcp(void *status)
{
    struct perf_buffer *pb = NULL;
    struct tcp_bpf *skel = NULL;
    int err = 0;

    err = init_bpf_tcp(&skel, &pb);
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

    err = poll_bpf_tcp(pb, &((struct status *)status)->exiting);

cleanup:
    redisFree(redis_ctx);
    cleanup_bpf_tcp(skel, pb);

    ((struct status *)status)->tcp_result = err;
    ((struct status *)status)->exiting = true;

    return NULL;
}
