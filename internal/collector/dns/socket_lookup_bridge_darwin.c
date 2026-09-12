#include "socket_lookup_bridge_darwin.h"

#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/proc_info.h>

int get_socket_local_endpoint(int pid, int fd, char *ip, int ip_len,
                              uint32_t *port) {
  struct socket_fdinfo info;

  memset(&info, 0, sizeof(info));

  int ret = proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &info, sizeof(info));

  if (ret != sizeof(info)) {
    return 0;
  }

  if (info.psi.soi_family == AF_INET) {
    struct in_sockinfo *in = &info.psi.soi_proto.pri_in;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_addr.s_addr = in->insi_laddr.ina_46.i46a_addr4.s_addr;

    if (inet_ntop(AF_INET, &addr.sin_addr, ip, ip_len) == NULL) {
      return 0;
    }

    *port = (uint32_t)ntohs((uint16_t)in->insi_lport);

    return 1;
  }

  if (info.psi.soi_family == AF_INET6) {
    struct in_sockinfo *in = &info.psi.soi_proto.pri_in;

    if (inet_ntop(AF_INET6, &in->insi_laddr.ina_6, ip, ip_len) == NULL) {
      return 0;
    }

    *port = (uint32_t)ntohs((uint16_t)in->insi_lport);

    return 1;
  }

  return 0;
}
