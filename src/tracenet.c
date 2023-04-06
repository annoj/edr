#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <hiredis/hiredis.h>
#include "tracenet.skel.h"
#include "tracenet.h"

static volatile bool exiting = false;
redisContext *redis_ctx = NULL;

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

redisContext *init_redis()
{
    redisContext *c = redisConnect(REDIS_HOST, REDIS_PORT);

    if (c->err) {
        fprintf(stderr, "Could not connect to redis, error: %s\n", c->errstr);
        return NULL;
    }

    return c;
}

void cleanup_redis(redisContext *c)
{
    if (!c) {
        redisFree(c);
    }
}

struct store_event {
    time_t t;
    int pid;
    uint8_t version;
    uint16_t id;
    uint8_t protocol;
    char saddr[16];
    char daddr[16];
};

int store_network_event(struct store_event *e, redisContext *ctx)
{
    size_t query_sz = 0xffff;
    char query[query_sz];
    redisReply *reply;

    snprintf(query, query_sz,
            "MERGE (p:Process {pid: %d}) "
            "CREATE (p)-[:HAS_NETWORK_CONNECTION]->(:Connection {"
                "ts: %ld, "
                "version: %d, "
                "id: %d, "
                "protocol: %d, "
                "saddr: '%s', "
                "daddr: '%s'"
            "})",
            e->pid,e->t, e->version, e->id, e->protocol, e->saddr, e->daddr);

    reply = redisCommand(ctx, "GRAPH.QUERY %s %s", REDIS_DATABASE, query);

    if (!reply) {
        fprintf(stderr, "Could not store event\n");
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

void ipv4_to_string(char ipstr[16], __be32 addr)
{
    union ipv4_addr {
        __be32 bytes;
        uint8_t octets[4];
    } a;

    a.bytes = addr;

    snprintf(ipstr, 16, "%d.%d.%d.%d", a.octets[0], a.octets[1], a.octets[2], a.octets[3]);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct store_event e;
    struct iphdr *ip_header = &((struct event *)data)->ip_header;

    time(&e.t);

    e.pid = ((struct event *)data)->pid;
    e.version = ip_header->version;
    e.id = ip_header->id;
    e.protocol = ip_header->protocol;

    ipv4_to_string(e.saddr, ip_header->saddr);
    ipv4_to_string(e.daddr, ip_header->daddr);

    printf("pid: %d, saddr: %s, daddr: %s\n", e.pid, e.saddr, e.daddr);

    store_network_event(&e, redis_ctx);
}

void cleanup_bpf_tracenet(struct tracenet_bpf *skel, struct perf_buffer *pb)
{
    perf_buffer__free(pb);
    tracenet_bpf__destroy(skel);
}

int init_bpf_tracenet(struct tracenet_bpf **skel, struct perf_buffer **pb)
{
    int err;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    *skel = tracenet_bpf__open();
    if (!*skel) {
        fprintf(stderr, "Failed to open BPF skeleton.\n");
        return 1;
    }

    err = tracenet_bpf__load(*skel);
    if (err) {
        fprintf(stderr, "Failed to attach to BPF skeleton.\n");
        goto out;
    }

    err = tracenet_bpf__attach(*skel);
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
        cleanup_bpf_tracenet(*skel, *pb);
    }

    return err;
}

int poll_bpf_tracenet(struct perf_buffer *pb)
{
    int err = 0;

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

    return err;
}

int main(int argc, char **argv)
{
    struct perf_buffer *pb = NULL;
    struct tracenet_bpf *skel = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = init_bpf_tracenet(&skel, &pb);
    if (err) {
        goto cleanup;
    }

    redis_ctx = init_redis();
    if (!redis_ctx) {
        fprintf(stderr, "Failed to initialize redis context.\n");
        goto cleanup;
    }

    err = poll_bpf_tracenet(pb);

cleanup:
    cleanup_redis(redis_ctx);
    cleanup_bpf_tracenet(skel, pb);

    return err < 0 ? -err : 0;
}
