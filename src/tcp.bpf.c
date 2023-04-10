#include "tcp.h"
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct tcp_event);
} heap SEC(".maps");

SEC("tp/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct tcp_event *e;
	int zero = 0;

	// This should allocate/reserve memory for e
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		return 0;
	}

    e->pid = BPF_CORE_READ(ctx, ent.pid);
    e->oldstate = BPF_CORE_READ(ctx, oldstate);
    e->newstate = BPF_CORE_READ(ctx, newstate);
    e->sport = BPF_CORE_READ(ctx, sport);
    e->dport = BPF_CORE_READ(ctx, dport);
    BPF_CORE_READ_INTO(&e->saddr, ctx, saddr);
    BPF_CORE_READ_INTO(&e->daddr, ctx, daddr);
    BPF_CORE_READ_INTO(&e->saddr_v6, ctx, saddr_v6);
    BPF_CORE_READ_INTO(&e->saddr_v6, ctx, saddr_v6);

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

    return 0;
}