#ifndef __TCP_H_
#define __TCP_H_

struct tcp_outbound_event {
        unsigned int pid;
        int oldstate;
        int newstate;
        unsigned int sport;
        unsigned int dport;
        unsigned int family;
        unsigned char protocol;
        unsigned char saddr[4];
        unsigned char daddr[4];
        unsigned char saddr_v6[16];
        unsigned char daddr_v6[16];
};

void *trace_tcp(void *exiting);

#endif
