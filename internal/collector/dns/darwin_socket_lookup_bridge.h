#ifndef SENTINEL_DARWIN_SOCKET_LOOKUP_BRIDGE_H
#define SENTINEL_DARWIN_SOCKET_LOOKUP_BRIDGE_H

#include <libproc.h>
#include <stdint.h>
#include <sys/proc_info.h>
#include <sys/types.h>

int get_socket_local_endpoint(int pid, int fd, char *ip, int ip_len,
                              uint32_t *port);

#endif
