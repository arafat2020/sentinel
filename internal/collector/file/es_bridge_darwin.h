#ifndef SENTINEL_ES_BRIDGE_H
#define SENTINEL_ES_BRIDGE_H

#include <stdint.h>

typedef struct sentinel_es_client sentinel_es_client;

int sentinel_es_client_create(
    sentinel_es_client **out_client
);

int sentinel_es_client_subscribe(
    sentinel_es_client *client
);

void sentinel_es_client_delete(
    sentinel_es_client *client
);

#endif