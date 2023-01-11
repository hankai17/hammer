#include <fcntl.h>
#include <assert.h>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

#include "socket_ops.hh"
#include "util.hh"
#include "log.hh"
#include "uv_errno.hh"

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");

    static inline std::string my_inet_ntop(int af, const void *addr) {
        std::string ret;
        ret.resize(128);
        if (!inet_ntop(af, const_cast<void*>(addr), (char *) ret.data(), ret.size())) {
            ret.clear();
        } else {
            ret.resize(strlen(ret.data()));
        }
        return ret;
    }
    
    static inline bool support_ipv6_l() {
        auto fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (fd == -1) {
            return false;
        }
        close(fd);
        return true;
    }
    
    static inline bool support_ipv6() {
        static auto flag = support_ipv6_l();
        return flag;
    }
    
    std::string SocketOps::inet_ntoa(const struct in_addr &addr) {
        return my_inet_ntop(AF_INET, &addr);
    }
    
    std::string SocketOps::inet_ntoa(const struct in6_addr &addr) {
        return my_inet_ntop(AF_INET6, &addr);
    }
    
    std::string SocketOps::inet_ntoa(const struct sockaddr *addr) {
        switch (addr->sa_family) {
            case AF_INET: return SocketOps::inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
            case AF_INET6: {
                if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)addr)->sin6_addr)) {
                    struct in_addr addr4;
                    memcpy(&addr4, 12 + (char *)&(((struct sockaddr_in6 *)addr)->sin6_addr), 4);
                    return SocketOps::inet_ntoa(addr4);
                }
                return SocketOps::inet_ntoa(((struct sockaddr_in6 *)addr)->sin6_addr);
            }
            default: assert(false); return "";
        }
    }
    
    uint16_t SocketOps::inet_port(const struct sockaddr *addr) {
        switch (addr->sa_family) {
            case AF_INET: return ntohs(((struct sockaddr_in *)addr)->sin_port);
            case AF_INET6: return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
            default: assert(false); return 0;
        }
    }
    
    int SocketOps::setCloseWait(int fd, int second) {
        linger m_sLinger;
        //在调用closesocket()时还有数据未发送完，允许等待
        // 若m_sLinger.l_onoff=0;则调用closesocket()后强制关闭
        m_sLinger.l_onoff = (second > 0);
        m_sLinger.l_linger = second; //设置等待时间为x秒
        int ret = setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &m_sLinger, sizeof(linger));
        if (ret == -1) {
    #ifndef _WIN32
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_LINGER failed";
    #endif
        }
        return ret;
    }
    
    int SocketOps::setNoDelay(int fd, bool on) {
        int opt = on ? 1 : 0;
        int ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &opt, static_cast<socklen_t>(sizeof(opt)));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt TCP_NODELAY failed";
        }
        return ret;
    }
    
    int SocketOps::setReuseable(int fd, bool on, bool reuse_port) {
        int opt = on ? 1 : 0;
        int ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, static_cast<socklen_t>(sizeof(opt)));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_REUSEADDR failed";
            return ret;
        }
    #if defined(SO_REUSEPORT)
        if (reuse_port) {
            ret = setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (char *) &opt, static_cast<socklen_t>(sizeof(opt)));
            if (ret == -1) {
                HAMMER_LOG_WARN(g_logger) << "setsockopt SO_REUSEPORT failed";
            }
        }
    #endif
        return ret;
    }
    
    int SocketOps::setBroadcast(int fd, bool on) {
        int opt = on ? 1 : 0;
        int ret = setsockopt(fd, SOL_SOCKET, SO_BROADCAST, (char *) &opt, static_cast<socklen_t>(sizeof(opt)));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_BROADCAST failed";
        }
        return ret;
    }
    
    int SocketOps::setKeepAlive(int fd, bool on) {
        int opt = on ? 1 : 0;
        int ret = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *) &opt, static_cast<socklen_t>(sizeof(opt)));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_KEEPALIVE failed";
        }
        return ret;
    }
    
    int SocketOps::setCloExec(int fd, bool on) {
        int flags = fcntl(fd, F_GETFD);
        if (flags == -1) {
            HAMMER_LOG_WARN(g_logger) << "fcntl F_GETFD failed";
            return -1;
        }
        if (on) {
            flags |= FD_CLOEXEC;
        } else {
            int cloexec = FD_CLOEXEC;
            flags &= ~cloexec;
        }
        int ret = fcntl(fd, F_SETFD, flags);
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "fcntl F_SETFD failed";
            return -1;
        }
        return ret;
    }
    
    int SocketOps::setNoSigpipe(int fd) {
    #if defined(SO_NOSIGPIPE)
        int set = 1;
        auto ret = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &set, sizeof(int));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_NOSIGPIPE failed";
        }
        return ret;
    #else
        return -1;
    #endif
    }
    
    int SocketOps::setNoBlocked(int fd, bool noblock) {
        int ul = noblock;
        int ret = ioctl(fd, FIONBIO, &ul);
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "ioctl FIONBIO failed";
        }
        return ret;
    }
    
    int SocketOps::setRecvBuf(int fd, int size) {
        int ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_RCVBUF failed";
        }
        return ret;
    }
    
    int SocketOps::setSendBuf(int fd, int size) {
        int ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &size, sizeof(size));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt SO_SNDBUF failed";
        }
        return ret;
    }
    
    class DNSCache { // singleton
    public:
        static DNSCache &Instance() {
            static DNSCache instance;
            return instance;
        }

        bool getDomainIP(const char *host, sockaddr_storage &storage, int ai_family = AF_INET,
                         int ai_socktype = SOCK_STREAM, int ai_protocol = IPPROTO_TCP, int expire_sec = 60) {
            try {
                storage = SocketOps::make_sockaddr(host, 0);
                return true;
            } catch (...) {
                auto item = getCacheDomainIP(host, expire_sec);
                if (!item) {
                    item = getSystemDomainIP(host);
                    if (item) {
                        setCacheDomainIP(host, item);
                    }
                }
                if (item) {
                    auto addr = getPerferredAddress(item.get(), ai_family, ai_socktype, ai_protocol);
                    memcpy(&storage, addr->ai_addr, addr->ai_addrlen);
                }
                return (bool)item;
            }
        }
    
    private:
        class DNSItem {
        public:
            std::shared_ptr<struct addrinfo> addr_info;
            time_t create_time;
        };
    
        std::shared_ptr<struct addrinfo> getCacheDomainIP(const char *host, int expire) {
            std::lock_guard<std::mutex> lock(m_mutex);
            auto it = m_dns_cache.find(host);
            if (it == m_dns_cache.end()) {
                return nullptr;
            }
            if (it->second.create_time + expire < time(nullptr)) {
                m_dns_cache.erase(it);
                return nullptr;
            }
            return it->second.addr_info;
        }
    
        void setCacheDomainIP(const char *host, std::shared_ptr<struct addrinfo> addr) {
            std::lock_guard<std::mutex> lock(m_mutex);
            DNSItem item;
            item.addr_info = std::move(addr);
            item.create_time = time(nullptr);
            m_dns_cache[host] = std::move(item);
        }
    
        std::shared_ptr<struct addrinfo> getSystemDomainIP(const char *host) {
            struct addrinfo *answer = nullptr;
            //阻塞式dns解析域名 可能被打断
            int ret = -1;
            do {
                ret = getaddrinfo(host, nullptr, nullptr, &answer);
            } while (ret == -1 && get_uv_error(true) == UV_EINTR);
    
            if (!answer) {
                HAMMER_LOG_WARN(g_logger) << "getaddrinfo failed: " << host;
                return nullptr;
            }
            return std::shared_ptr<struct addrinfo>(answer, freeaddrinfo);
        }
    
        struct addrinfo *getPerferredAddress(struct addrinfo *answer, int ai_family, int ai_socktype, int ai_protocol) {
            auto ptr = answer;
            while (ptr) {
                if (ptr->ai_family == ai_family && ptr->ai_socktype == ai_socktype && ptr->ai_protocol == ai_protocol) {
                    return ptr;
                }
                ptr = ptr->ai_next;
            }
            return answer;
        }
    
    private:
        std::mutex m_mutex;
        std::unordered_map<std::string, DNSItem> m_dns_cache;
    };
    
    bool SocketOps::getDomainIP(const char *host, uint16_t port, struct sockaddr_storage &addr,
                               int ai_family, int ai_socktype, int ai_protocol, int expire_sec) {
        bool flag = DNSCache::Instance().getDomainIP(host, addr, ai_family, ai_socktype, ai_protocol, expire_sec);
        if (flag) {
            switch (addr.ss_family ) {
                case AF_INET : ((sockaddr_in *) &addr)->sin_port = htons(port); break;
                case AF_INET6 : ((sockaddr_in6 *) &addr)->sin6_port = htons(port); break;
                default: assert(0); break;
            }
        }
        return flag;
    }
    
    static int set_ipv6_only(int fd, bool flag) {
        int opt = flag;
        int ret = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&opt, sizeof opt);
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IPV6_V6ONLY failed";
        }
        return ret;
    }
    
    static int bind_sock6(int fd, const char *ifr_ip, uint16_t port) {
        set_ipv6_only(fd, false);
        struct sockaddr_in6 addr;
        bzero(&addr, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (1 != inet_pton(AF_INET6, ifr_ip, &(addr.sin6_addr))) {
            if (strcmp(ifr_ip, "0.0.0.0")) {
                HAMMER_LOG_WARN(g_logger) << "inet_pton to ipv6 address failed: " << ifr_ip;
            }
            addr.sin6_addr = IN6ADDR_ANY_INIT;
        }
        if (::bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
            HAMMER_LOG_WARN(g_logger) << "Bind socket failed: " << get_uv_errmsg(true);
            return -1;
        }
        return 0;
    }
    
    static int bind_sock4(int fd, const char *ifr_ip, uint16_t port) {
        struct sockaddr_in addr;
        bzero(&addr, sizeof(addr));
    
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (1 != inet_pton(AF_INET, ifr_ip, &(addr.sin_addr))) {
            if (strcmp(ifr_ip, "::")) {
                HAMMER_LOG_WARN(g_logger) << "inet_pton to ipv4 address failed: " << ifr_ip;
            }
            addr.sin_addr.s_addr = INADDR_ANY;
        }
        if (::bind(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
            HAMMER_LOG_WARN(g_logger) << "Bind socket failed: " << get_uv_errmsg(true);
            return -1;
        }
        return 0;
    }
    
    static int bind_sock(int fd, const char *ifr_ip, uint16_t port, int family) {
        switch (family) {
            case AF_INET: return bind_sock4(fd, ifr_ip, port);
            case AF_INET6: return bind_sock6(fd, ifr_ip, port);
            default: assert(0); return -1;
        }
    }
    
    int SocketOps::connect(const char *host, uint16_t port, bool async, const char *local_ip, uint16_t local_port) {
        sockaddr_storage addr;
        // addr返回正确的
        if (!getDomainIP(host, port, addr, AF_INET, SOCK_STREAM, IPPROTO_TCP)) {
            return -1;
        }
    
        int sockfd = (int) socket(addr.ss_family, SOCK_STREAM, IPPROTO_TCP);
        if (sockfd < 0) {
            HAMMER_LOG_WARN(g_logger) << "Create socket failed: " << host;
            return -1;
        }
    
        setReuseable(sockfd);
        setNoSigpipe(sockfd);
        setNoBlocked(sockfd, async);
        setNoDelay(sockfd);
        setSendBuf(sockfd);
        setRecvBuf(sockfd);
        setCloseWait(sockfd);
        setCloExec(sockfd);
    
        if (bind_sock(sockfd, local_ip, local_port, addr.ss_family) == -1) {
            close(sockfd);
            return -1;
        }
    
        if (::connect(sockfd, (sockaddr *) &addr, get_sock_len((sockaddr *)&addr)) == 0) {
            return sockfd;
        }
        if (async && get_uv_error(true) == UV_EAGAIN) {
            return sockfd;
        }
        HAMMER_LOG_WARN(g_logger) << "Connect socket to " << host << " " << port << " failed: " << get_uv_errmsg(true);
        close(sockfd);
        return -1;
    }
    
    int SocketOps::listen(const uint16_t port, const char *local_ip, int back_log) {
        int fd = -1;
        int family = support_ipv6() ? (is_ipv4(local_ip) ? AF_INET : AF_INET6) : AF_INET;
        if ((fd = (int)socket(family, SOCK_STREAM, IPPROTO_TCP)) == -1) {
            HAMMER_LOG_WARN(g_logger) << "Create socket failed: " << get_uv_errmsg(true);
            return -1;
        }
    
        setReuseable(fd, true, false);
        setNoBlocked(fd);
        setCloExec(fd);
        int value = 0;
        setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &value, sizeof(int));
    
        if (bind_sock(fd, local_ip, port, family) == -1) {
            close(fd);
            return -1;
        }
    
        //开始监听
        if (::listen(fd, back_log) == -1) {
            HAMMER_LOG_WARN(g_logger) << "Listen socket failed: " << get_uv_errmsg(true);
            close(fd);
            return -1;
        }
    
        return fd;
    }
    
    int SocketOps::getSockError(int fd) {
        int opt;
        socklen_t optLen = static_cast<socklen_t>(sizeof(opt));
    
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *) &opt, &optLen) < 0) {
            return get_uv_error(true);
        } else {
            return uv_translate_posix_error(opt);
        }
    }
    
    using getsockname_type = decltype(getsockname);
    
    static bool get_socket_addr(int fd, struct sockaddr_storage &addr, getsockname_type func) {
        socklen_t addr_len = sizeof(addr);
        if (-1 == func(fd, (struct sockaddr *)&addr, &addr_len)) {
            return false;
        }
        return true;
    }
    
    bool SocketOps::get_sock_local_addr(int fd, struct sockaddr_storage &addr) {
        return get_socket_addr(fd, addr, getsockname);
    }
    
    bool SocketOps::get_sock_peer_addr(int fd, struct sockaddr_storage &addr) {
        return get_socket_addr(fd, addr, getpeername);
    }
    
    static std::string get_socket_ip(int fd, getsockname_type func) {
        struct sockaddr_storage addr;
        if (!get_socket_addr(fd, addr, func)) {
            return "";
        }
        return SocketOps::inet_ntoa((struct sockaddr *)&addr);
    }
    
    static uint16_t get_socket_port(int fd, getsockname_type func) {
        struct sockaddr_storage addr;
        if (!get_socket_addr(fd, addr, func)) {
            return 0;
        }
        return SocketOps::inet_port((struct sockaddr *)&addr);
    }
    
    std::string SocketOps::get_local_ip(int fd) {
        return get_socket_ip(fd, getsockname);
    }
    
    std::string SocketOps::get_peer_ip(int fd) {
        return get_socket_ip(fd, getpeername);
    }
    
    uint16_t SocketOps::get_local_port(int fd) {
        return get_socket_port(fd, getsockname);
    }
    
    uint16_t SocketOps::get_peer_port(int fd) {
        return get_socket_port(fd, getpeername);
    }
    
    template<typename FUN>
    void foreach_netAdapter_posix(FUN &&fun) { //type: struct ifreq *
        struct ifconf ifconf;
        char buf[1024 * 10];
        //初始化ifconf
        ifconf.ifc_len = sizeof(buf);
        ifconf.ifc_buf = buf;
        int sockfd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0) {
            HAMMER_LOG_WARN(g_logger) << "Create socket failed: " << get_uv_errmsg(true);
            return;
        }
        if (-1 == ioctl(sockfd, SIOCGIFCONF, &ifconf)) {    //获取所有接口信息
            HAMMER_LOG_WARN(g_logger) << "ioctl SIOCGIFCONF failed: " << get_uv_errmsg(true);
            close(sockfd);
            return;
        }
        close(sockfd);
        //接下来一个一个的获取IP地址
        struct ifreq * adapter = (struct ifreq*) buf;
        for (int i = (ifconf.ifc_len / sizeof(struct ifreq)); i > 0; --i,++adapter) {
            if(fun(adapter)){
                break;
            }
        }
    }
    
    bool check_ip(std::string &address, const std::string &ip) {
        if (ip != "127.0.0.1" && ip != "0.0.0.0") {
            /*获取一个有效IP*/
            address = ip;
            uint32_t addressInNetworkOrder = htonl(inet_addr(ip.data()));
            if (/*(addressInNetworkOrder >= 0x0A000000 && addressInNetworkOrder < 0x0E000000) ||*/
                (addressInNetworkOrder >= 0xAC100000 && addressInNetworkOrder < 0xAC200000) ||
                (addressInNetworkOrder >= 0xC0A80000 && addressInNetworkOrder < 0xC0A90000)) {
                //A类私有IP地址：
                //10.0.0.0～10.255.255.255
                //B类私有IP地址：
                //172.16.0.0～172.31.255.255
                //C类私有IP地址：
                //192.168.0.0～192.168.255.255
                //如果是私有地址 说明在nat内部
    
                /* 优先采用局域网地址，该地址很可能是wifi地址
                 * 一般来说,无线路由器分配的地址段是BC类私有ip地址
                 * 而A类地址多用于蜂窝移动网络
                 */
                return true;
            }
        }
        return false;
    }
    
    std::string SocketOps::get_local_ip() {
        std::string address = "127.0.0.1";
        foreach_netAdapter_posix([&](struct ifreq *adapter){
            std::string ip = SocketOps::inet_ntoa(&(adapter->ifr_addr));
            if (strstr(adapter->ifr_name, "docker")) {
                return false;
            }
            return check_ip(address,ip);
        });
        return address;
    }
    
    std::vector<std::map<std::string, std::string> > SocketOps::getInterfaceList() {
        std::vector<std::map<std::string, std::string> > ret;
        foreach_netAdapter_posix([&](struct ifreq *adapter){
            std::map<std::string,std::string> obj;
            obj["ip"] = SocketOps::inet_ntoa(&(adapter->ifr_addr));
            obj["name"] = adapter->ifr_name;
            ret.emplace_back(std::move(obj));
            return false;
        });
        return ret;
    }
    
    int SocketOps::bindUdpSock(const uint16_t port, const char *local_ip, bool enable_reuse) {
        int fd = -1;
        int family = support_ipv6() ? (is_ipv4(local_ip) ? AF_INET : AF_INET6) : AF_INET;
        if ((fd = (int)socket(family, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            HAMMER_LOG_WARN(g_logger) << "Create socket failed: " << get_uv_errmsg(true);
            return -1;
        }
        if (enable_reuse) {
            setReuseable(fd);
        }
        setNoSigpipe(fd);
        setNoBlocked(fd);
        setSendBuf(fd);
        setRecvBuf(fd);
        setCloseWait(fd);
        setCloExec(fd);
    
        if (bind_sock(fd, local_ip, port, family) == -1) {
            close(fd);
            return -1;
        }
        return fd;
    }
    
    int SocketOps::dissolveUdpSock(int fd) {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        if (-1 == getsockname(fd, (struct sockaddr *)&addr, &addr_len)) {
            return -1;
        }
        addr.ss_family = AF_UNSPEC;
        if (-1 == ::connect(fd, (struct sockaddr *)&addr, addr_len) && get_uv_error() != UV_EAFNOSUPPORT) {
            // mac/ios时返回EAFNOSUPPORT错误
            HAMMER_LOG_WARN(g_logger) << "Connect socket AF_UNSPEC failed: " << get_uv_errmsg(true);
            return -1;
        }
       return 0;
    }
    
    std::string SocketOps::get_ifr_ip(const char *if_name) {
        std::string ret;
        foreach_netAdapter_posix([&](struct ifreq *adapter){
            if(strcmp(adapter->ifr_name,if_name) == 0) {
                ret = SocketOps::inet_ntoa(&(adapter->ifr_addr));
                return true;
            }
            return false;
        });
        return ret;
    }
    
    std::string SocketOps::get_ifr_name(const char *local_ip) {
        std::string ret = "en0";
        foreach_netAdapter_posix([&](struct ifreq *adapter){
            std::string ip = SocketOps::inet_ntoa(&(adapter->ifr_addr));
            if(ip == local_ip) {
                ret = adapter->ifr_name;
                return true;
            }
            return false;
        });
        return ret;
    }
    
    std::string SocketOps::get_ifr_mask(const char *if_name) {
        int fd;
        struct ifreq ifr_mask;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
            HAMMER_LOG_WARN(g_logger) << "Create socket failed: " << get_uv_errmsg(true);
            return "";
        }
        memset(&ifr_mask, 0, sizeof(ifr_mask));
        strncpy(ifr_mask.ifr_name, if_name, sizeof(ifr_mask.ifr_name) - 1);
        if ((ioctl(fd, SIOCGIFNETMASK, &ifr_mask)) < 0) {
            HAMMER_LOG_WARN(g_logger) << "ioctl SIOCGIFNETMASK on " << if_name << " failed: " << get_uv_errmsg(true);
            close(fd);
            return "";
        }
        close(fd);
        return SocketOps::inet_ntoa(&(ifr_mask.ifr_netmask));
    }
    
    std::string SocketOps::get_ifr_brdaddr(const char *if_name) {
        int fd;
        struct ifreq ifr_mask;
        fd = socket( AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
            HAMMER_LOG_WARN(g_logger) << "Create socket failed: " << get_uv_errmsg(true);
            return "";
        }
        memset(&ifr_mask, 0, sizeof(ifr_mask));
        strncpy(ifr_mask.ifr_name, if_name, sizeof(ifr_mask.ifr_name) - 1);
        if ((ioctl(fd, SIOCGIFBRDADDR, &ifr_mask)) < 0) {
            HAMMER_LOG_WARN(g_logger) << "ioctl SIOCGIFBRDADDR failed: " << get_uv_errmsg(true);
            close(fd);
            return "";
        }
        close(fd);
        return SocketOps::inet_ntoa(&(ifr_mask.ifr_broadaddr));
    }
    
    #define ip_addr_netcmp(addr1, addr2, mask) (((addr1) & (mask)) == ((addr2) & (mask)))
    
    bool SocketOps::in_same_lan(const char *myIp, const char *dstIp) {
        std::string mask = get_ifr_mask(get_ifr_name(myIp).data());
        return ip_addr_netcmp(inet_addr(myIp), inet_addr(dstIp), inet_addr(mask.data()));
    }
    
    static void clearMulticastAllSocketOption(int socket) {
    #if defined(IP_MULTICAST_ALL)
        // This option is defined in modern versions of Linux to overcome a bug in the Linux kernel's default behavior.
        // When set to 0, it ensures that we receive only packets that were sent to the specified IP multicast address,
        // even if some other process on the same system has joined a different multicast group with the same port number.
        int multicastAll = 0;
        (void)setsockopt(socket, IPPROTO_IP, IP_MULTICAST_ALL, (void*)&multicastAll, sizeof multicastAll);
        // Ignore the call's result.  Should it fail, we'll still receive packets (just perhaps more than intended)
    #endif
    }
    
    int SocketOps::setMultiTTL(int fd, uint8_t ttl) {
        int ret = -1;
    #if defined(IP_MULTICAST_TTL)
        ret = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (char *) &ttl, sizeof(ttl));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_MULTICAST_TTL failed";
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    int SocketOps::setMultiIF(int fd, const char *local_ip) {
        int ret = -1;
    #if defined(IP_MULTICAST_IF)
        struct in_addr addr;
        addr.s_addr = inet_addr(local_ip);
        ret = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (char *) &addr, sizeof(addr));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_MULTICAST_IF failed";
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    int SocketOps::setMultiLOOP(int fd, bool accept) {
        int ret = -1;
    #if defined(IP_MULTICAST_LOOP)
        uint8_t loop = accept;
        ret = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, (char *) &loop, sizeof(loop));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_MULTICAST_LOOP failed";
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    int SocketOps::joinMultiAddr(int fd, const char *addr, const char *local_ip) {
        int ret = -1;
    #if defined(IP_ADD_MEMBERSHIP)
        struct ip_mreq imr;
        imr.imr_multiaddr.s_addr = inet_addr(addr);
        imr.imr_interface.s_addr = inet_addr(local_ip);
        ret = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &imr, sizeof(struct ip_mreq));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_ADD_MEMBERSHIP failed: " << get_uv_errmsg(true);
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    int SocketOps::leaveMultiAddr(int fd, const char *addr, const char *local_ip) {
        int ret = -1;
    #if defined(IP_DROP_MEMBERSHIP)
        struct ip_mreq imr;
        imr.imr_multiaddr.s_addr = inet_addr(addr);
        imr.imr_interface.s_addr = inet_addr(local_ip);
        ret = setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char *) &imr, sizeof(struct ip_mreq));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_DROP_MEMBERSHIP failed: " << get_uv_errmsg(true);
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    template<typename A, typename B>
    static inline void write4Byte(A &&a, B &&b) {
        memcpy(&a, &b, sizeof(a));
    }
    
    int SocketOps::joinMultiAddrFilter(int fd, const char *addr, const char *src_ip, const char *local_ip) {
        int ret = -1;
    #if defined(IP_ADD_SOURCE_MEMBERSHIP)
        struct ip_mreq_source imr;
    
        write4Byte(imr.imr_multiaddr, inet_addr(addr));
        write4Byte(imr.imr_sourceaddr, inet_addr(src_ip));
        write4Byte(imr.imr_interface, inet_addr(local_ip));
    
        ret = setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, (char *) &imr, sizeof(struct ip_mreq_source));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_ADD_SOURCE_MEMBERSHIP failed: " << get_uv_errmsg(true);
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    int SocketOps::leaveMultiAddrFilter(int fd, const char *addr, const char *src_ip, const char *local_ip) {
        int ret = -1;
    #if defined(IP_DROP_SOURCE_MEMBERSHIP)
        struct ip_mreq_source imr;
    
        write4Byte(imr.imr_multiaddr, inet_addr(addr));
        write4Byte(imr.imr_sourceaddr, inet_addr(src_ip));
        write4Byte(imr.imr_interface, inet_addr(local_ip));
    
        ret = setsockopt(fd, IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP, (char *) &imr, sizeof(struct ip_mreq_source));
        if (ret == -1) {
            HAMMER_LOG_WARN(g_logger) << "setsockopt IP_DROP_SOURCE_MEMBERSHIP failed: " << get_uv_errmsg(true);
        }
    #endif
        clearMulticastAllSocketOption(fd);
        return ret;
    }
    
    bool SocketOps::is_ipv4(const char *host) {
        struct in_addr addr;
        return 1 == inet_pton(AF_INET, host, &addr);
    }
    
    bool SocketOps::is_ipv6(const char *host) {
        struct in6_addr addr;
        return 1 == inet_pton(AF_INET6, host, &addr);
    }
    
    socklen_t SocketOps::get_sock_len(const struct sockaddr *addr) {
        switch (addr->sa_family) {
            case AF_INET : return sizeof(sockaddr_in);
            case AF_INET6 : return sizeof(sockaddr_in6);
            default: assert(0); return 0;
        }
    }
    
    struct sockaddr_storage SocketOps::make_sockaddr(const char *host, uint16_t port) {
        struct sockaddr_storage storage;
        bzero(&storage, sizeof(storage));
    
        struct in_addr addr;
        struct in6_addr addr6;
        if (1 == inet_pton(AF_INET, host, &addr)) { // 点分十进制的ip
            reinterpret_cast<struct sockaddr_in &>(storage).sin_addr = addr;
            reinterpret_cast<struct sockaddr_in &>(storage).sin_family = AF_INET;
            reinterpret_cast<struct sockaddr_in &>(storage).sin_port = htons(port);
            return storage;
        }
        if (1 == inet_pton(AF_INET6, host, &addr6)) {
            reinterpret_cast<struct sockaddr_in6 &>(storage).sin6_addr = addr6;
            reinterpret_cast<struct sockaddr_in6 &>(storage).sin6_family = AF_INET6;
            reinterpret_cast<struct sockaddr_in6 &>(storage).sin6_port = htons(port);
            return storage;
        }
        throw std::invalid_argument(std::string("Not ip address: ") + host);
    }

}
