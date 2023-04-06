#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "tracenet.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// root@ebpf-dev:/sys/kernel/debug/tracing/events/net/netif_receive_skb# cat format 
// name: netif_receive_skb
// ID: 1404
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
// 
//         field:void * skbaddr;   offset:8;       size:8; signed:0;
//         field:unsigned int len; offset:16;      size:4; signed:0;
//         field:__data_loc char[] name;   offset:20;      size:4; signed:1;

struct trace_event_netif_receive_skb {
	struct trace_entry ent;
	struct sk_buff *skbaddr;
	unsigned int len;
	char __data_loc[0];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");

SEC("tp/net/netif_receive_skb")
int handle_net_event(struct trace_event_netif_receive_skb *ctx)
{
	int zero = 0;
	long err;
	struct event *e;

	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) {
		return 1;
	}

	e->pid = bpf_get_current_pid_tgid() >> 32; // Shift to only use pid
	bpf_printk("pid: %d\n", e->pid);

	if (!e->pid) {
		return 0;
	}

	struct sk_buff *skbaddr;
	err = bpf_probe_read(&skbaddr, sizeof(void *), &(ctx->skbaddr));
	if (err < 0) {
		bpf_printk("Reading ctx->skbaddr read failed: %d\n", err);
		return 1;
	}
	bpf_printk("skbaddr: %p\n", skbaddr);

	__u16 network_header;
	err = bpf_probe_read(&network_header, sizeof(network_header), &skbaddr->network_header);
	if (err < 0) {
		bpf_printk("Reading skbaddr->network_header failed: %d\n", err);
		return 1;
	}
	bpf_printk("network_header: 0x%x\n", network_header);

	err = bpf_probe_read(&e->ip_header, sizeof(struct iphdr), &(skbaddr->head) + network_header);
	if (err < 0) {
		bpf_printk("Reading &(skbaddr->head) + e->network_header failed: %d\n", err);
		return 1;
	}

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

    return 0;
}