#ifndef HAMMER_SOCKET_OPS_H
#define HAMMER_SOCKET_OPS_H

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <cstring>
#include <cstdint>
#include <map>
#include <vector>
#include <string>

namespace hammer {

#define SOCKET_DEFAULT_BUF_SIZE (256 * 1024)

class SocketOps {
public:
    static int connect(const char *host, uint16_t port, bool async = true, const char *local_ip = "::", uint16_t local_port = 0);
    static int listen(const uint16_t port, const char *local_ip = "::", int back_log = 1024);
    static int bindUdpSock(const uint16_t port, const char *local_ip = "::", bool enable_reuse = true);
    static int dissolveUdpSock(int sock);
    static int setNoDelay(int fd, bool on = true);
    static int setNoSigpipe(int fd);
    static int setNoBlocked(int fd, bool noblock = true);
    static int setRecvBuf(int fd, int size = SOCKET_DEFAULT_BUF_SIZE);
    static int setSendBuf(int fd, int size = SOCKET_DEFAULT_BUF_SIZE);
    static int setReuseable(int fd, bool on = true, bool reuse_port = true);
    static int setBroadcast(int fd, bool on = true);
    static int setKeepAlive(int fd, bool on = true);
    static int setCloExec(int fd, bool on = true);
    static int setCloseWait(int sock, int second = 0);
    static bool getDomainIP(const char *host, uint16_t port, struct sockaddr_storage &addr, int ai_family = AF_INET,
                            int ai_socktype = SOCK_STREAM, int ai_protocol = IPPROTO_TCP, int expire_sec = 60);
    static int setMultiTTL(int sock, uint8_t ttl = 64);
    static int setMultiIF(int sock, const char *local_ip);
    static int setMultiLOOP(int fd, bool acc = false);
    static int joinMultiAddr(int fd, const char *addr, const char *local_ip = "0.0.0.0");
    static int leaveMultiAddr(int fd, const char *addr, const char *local_ip = "0.0.0.0");
    static int joinMultiAddrFilter(int sock, const char *addr, const char *src_ip, const char *local_ip = "0.0.0.0");
    static int leaveMultiAddrFilter(int fd, const char *addr, const char *src_ip, const char *local_ip = "0.0.0.0");
    static int getSockError(int fd);
    static std::vector<std::map<std::string, std::string>> getInterfaceList();
    static std::string get_local_ip();
    static std::string get_local_ip(int sock);
    static uint16_t get_local_port(int sock);
    static std::string get_peer_ip(int sock);
    static uint16_t get_peer_port(int sock);
    static std::string inet_ntoa(const struct in_addr &addr);
    static std::string inet_ntoa(const struct in6_addr &addr);
    static std::string inet_ntoa(const struct sockaddr *addr);
    static uint16_t inet_port(const struct sockaddr *addr);
    static struct sockaddr_storage make_sockaddr(const char *ip, uint16_t port);
    static socklen_t get_sock_len(const struct sockaddr *addr);
    static bool get_sock_local_addr(int fd, struct sockaddr_storage &addr);
    static bool get_sock_peer_addr(int fd, struct sockaddr_storage &addr);
    static std::string get_ifr_ip(const char *if_name);
    static std::string get_ifr_name(const char *local_op);
    static std::string get_ifr_mask(const char *if_name);
    static std::string get_ifr_brdaddr(const char *if_name);
    static bool in_same_lan(const char *src_ip, const char *dts_ip);
    static bool is_ipv4(const char *str);
    static bool is_ipv6(const char *str);
};

}
#endif
