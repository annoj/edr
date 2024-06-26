#ifndef __TRACENET_H
#define __TRACENET_H

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379
#define REDIS_DATABASE "EDR"

#define MAX_NET_DATA_LEN 1024

#ifndef __VMLINUX_H__
struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};
#endif

struct event {
	int pid;
	struct iphdr ip_header;
};

#endif