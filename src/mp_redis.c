#include <hiredis/hiredis.h>
#include <pthread.h>
#include <unistd.h>

void *run_redis_thread(void *arg)
{
    redisContext *ctx = redisConnect("127.0.0.1", 6379);
    size_t query_sz = 0xffff;
    char query[query_sz];
    redisReply *reply;

    sleep(5);

    redisFree(ctx);

    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t t1;
    pthread_t t2;

    pthread_create(&t1, NULL, run_redis_thread, NULL);
    pthread_create(&t2, NULL, run_redis_thread, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;
}