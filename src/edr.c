#include "edr.h"

#include ".h"

#include <assert.h>
#include <error.h>
#include <hiredis/hiredis.h>
#include <signal.h>
#include <string.h>

static void kill_all_threads()
{
    assert(0 && "Not implemented.");
}

static void sig_handler(int sig)
{
    switch (sig)
    {
    case SIGINT:
    case SIGTERM:
        printf("Received %s, exiting", strsignal(sig));
        kill_all_threads();
    }
}

int main(int argc, char **argv)
{
    // Register signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Check redis is available
    redisContext *c = redisConnect(REDIS_HOST, REDIS_PORT);
    if (c->err) {
        fprintf(stderr, "Could not connect to redis at %s:%d, error: %s\n", REDIS_HOST, REDIS_PORT, c->errstr);
        exit(1);
    }
    redisFree(c);

    // Start modules as threads

    // Join module threads
}