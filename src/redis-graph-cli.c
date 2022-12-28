#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis/hiredis.h>

void _print_redis_reply(redisReply *r, int indent) {
    switch (r->type) {
    case REDIS_REPLY_STRING:
        printf("%*sREDIS_REPLY_STRING: %s\n", indent, "", r->str);
        return;
    case REDIS_REPLY_INTEGER:
        printf("%*sREDIS_REPLY_INTEGER: %lld\n", indent, "", r->integer);
        return;
    case REDIS_REPLY_ARRAY: 
        for (int i = 0; i < r->elements; i++) {
            _print_redis_reply(r->element[i], indent + 4);
        }
        break;
	case REDIS_REPLY_ERROR:
		printf("REDIS_REPLY_ERROR: %s\n", r->str);
		break;
    default:
        fprintf(stderr, "Redis reply type %d is not implemented.\n", r->type);
    }
}

void print_redis_reply(redisReply *r) {
    _print_redis_reply(r, 0);
}

int main (int argc, const char **argv) {

    if (argc != 3) {
        return -1;
    }

    redisReply *reply;
    redisContext *c;

    c = redisConnect("127.0.0.1", 6379);
    if (c->err) {
        fprintf(stderr, "Could not connect to redis, error: %s\n", c->errstr);
        return -1;
    }

    const char *database = argv[1];
    const char *command = argv[2];

    reply = redisCommand(c, "GRAPH.QUERY %s %s", database, command);
    print_redis_reply(reply);

    freeReplyObject(reply);
    redisFree(c);

    return 0;
}
