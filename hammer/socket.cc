//
// Created by root on 12/6/22.
//

#include <sys/socket.h>
#include "socket.hh"
#include "log.hh"
#include "uv_errno.hh"
#include "socket_ops.hh"
#include "singleton.hh"

#define LOCK_GUARD(mutex) std::lock_guard<decltype(mutex)> lock(mutex)

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");

    static SocketException toSocketException(int error) {
        switch (error) {
            case 0:
            case UV_EAGAIN: return SocketException(ERRCode::SUCCESS, "success");
            case UV_ECONNREFUSED: return SocketException(ERRCode::REFUSE, uv_strerror(error), error);
            case UV_ETIMEDOUT: return SocketException(ERRCode::TIMEOUT, uv_strerror(error), error);
            default: return SocketException(ERRCode::OTHER, uv_strerror(error), error);
        }
    }

    static SocketException getSocketError(const SocketFD::ptr sock, bool try_errno = true) {
        int error = 0;
        int len = sizeof(int);
        getsockopt(sock->getFD(), SOL_SOCKET, SO_ERROR, (char*)&error, (socklen_t *)&len);
        if (error == 0) {
            if (try_errno) {
                error = get_uv_error(true);
            }
        } else {
            error = uv_translate_posix_error(error);
        }
        return toSocketException(error);
    }

    SocketNO::~SocketNO() {
        ::shutdown(m_fd, SHUT_RDWR);
        //HAMMER_LOG_DEBUG(g_logger) << "close SocketNO fd: " << m_fd;
        close(m_fd);
    }

    Socket::Socket(const EventPoller::ptr poller, bool enable_mutex)
            : m_poller(poller), m_socketFD_mutex(enable_mutex),
            m_event_cb_mutex(enable_mutex),
            m_write_buffer_waiting_mutex(enable_mutex),
            m_write_buffer_sending_mutex(enable_mutex) {
        if (!poller) {
            // TODO
        }
        m_write_buffer_waiting = std::make_shared<MBuffer>();
        m_write_buffer_sending = std::make_shared<MBuffer>();
    }

    void Socket::closeSocket() {
        m_conn_timer = nullptr;
        m_conn_cb = nullptr;

        LOCK_GUARD(m_socketFD_mutex);
        if (m_fd) {
            HAMMER_LOG_DEBUG(g_logger) << "closeSocket fd: " << m_fd->getFD();
        }
        m_fd = nullptr;
    }

    Socket::~Socket() {
        if (!m_poller->isCurrentThread()) {
            if (m_fd) {
                HAMMER_LOG_WARN(g_logger) << "~Socket fd: " << m_fd->getFD() << " in other thread";
            } else {
                HAMMER_LOG_WARN(g_logger) << "~Socket in other thread";
            }
            sleep(5);
            HAMMER_ASSERT(0);
        } else {
            HAMMER_LOG_DEBUG(g_logger) << "~Socket in local thread";
        }
        closeSocket();
    }

    Socket::ptr Socket::createSocket(const EventPoller::ptr &poller, bool enable_mutex) {
        return std::make_shared<Socket>(poller, enable_mutex);
    }

    Socket* Socket::createSocketPtr(const EventPoller::ptr &poller, bool enable_mutex) {
        return new Socket(poller, enable_mutex);
    }

    SocketFD::ptr Socket::setSocketFD(int fd) {
        closeSocket();
        auto socket = std::make_shared<SocketFD>(fd, SocketFD::SocketType::TCP, m_poller);
        LOCK_GUARD(m_socketFD_mutex);
        m_fd = socket;
        return socket;
    }

    std::string Socket::getLocalIP() {
        LOCK_GUARD(m_socketFD_mutex);
        if (!m_fd) {
            return "";
        }
        return SocketOps::get_local_ip(m_fd->getFD());
    }

    uint16_t Socket::getLocalPort() {
        LOCK_GUARD(m_socketFD_mutex);
        if (!m_fd) {
            return 0;
        }
        return SocketOps::get_local_port(m_fd->getFD());
    }

    std::string Socket::getPeerIP() {
        LOCK_GUARD(m_socketFD_mutex);
        if (!m_fd) {
            return "";
        }
        return SocketOps::get_peer_ip(m_fd->getFD());
    }

    uint16_t Socket::getPeerPort() {
        LOCK_GUARD(m_socketFD_mutex);
        if (!m_fd) {
            return 0;
        }
        return SocketOps::get_peer_port(m_fd->getFD());
    }

    static ssize_t recvFrom(int fd, void* buffer, size_t length, struct sockaddr_storage *addr, socklen_t len, int flags = 0) { // TODO optimize
        return ::recvfrom(fd, buffer, length, flags, (sockaddr*)addr, &len);
    }

    static ssize_t recvFrom(int fd, iovec* buffers, size_t length, struct sockaddr_storage *addr, socklen_t len, int flags = 0) {
        msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = (iovec*)buffers;
        msg.msg_iovlen = length;
        msg.msg_name = (void*)addr;
        msg.msg_namelen = len;
        return ::recvmsg(fd, &msg, flags);
    }

    static ssize_t sendTo(int fd, const void *buffer, size_t length, struct sockaddr_storage &to, socklen_t len, int flags = 0) {
        // if connected
        ssize_t ret = 0;
        do {
            ret = ::sendto(fd, buffer, length, flags, (sockaddr*)&to, len);
        } while (-1 == ret && UV_EINTR == get_uv_error(true));
        return ret;
    }

    static ssize_t sendTo(int fd, iovec* buffers, size_t length, struct sockaddr_storage *to = NULL, socklen_t len = 0, int flags = 0) {
        // if connected
        ssize_t ret = 0;
        do {
            msghdr msg;
            memset(&msg, 0, sizeof(msg));
            msg.msg_iov = (iovec*)buffers;
            msg.msg_iovlen = length;
            msg.msg_name = nullptr;
            msg.msg_namelen = 0;
            ret = ::sendmsg(fd, &msg, flags);
        } while (-1 == ret && UV_EINTR == get_uv_error(true));
        return ret;
    }

    bool Socket::emitErr(const SocketException &err) noexcept {
        {
            LOCK_GUARD(m_socketFD_mutex);
            if (!m_fd) {
                return false;
            }
        }
        closeSocket();
        std::weak_ptr<Socket> weak_self = shared_from_this();
        m_poller->async([weak_self, err]() {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return;
            }
            LOCK_GUARD(strong_self->getFdMutex());
            try {
                strong_self->getErrCB()(err);
            } catch (std::exception &e) {
                HAMMER_LOG_WARN(g_logger) << "Exception occurred when emit on_err: " << e.what();
            }
        });
        return true;
    }

    void Socket::enableRead(const SocketFD::ptr &sock) {
        if (m_read_enable) {
            return;
        }
        m_read_enable = true;
#if 0
        int flag = 0;
        m_poller->modEvent(sock->getFD(), flag | EventPoller::Event::READ | EventPoller::Event::ERROR);
#endif
    }

    void Socket::disableRead(const SocketFD::ptr &sock) {
        if (m_read_enable == false) {
            return;
        }
        m_read_enable = false;
#if 0
        int flag = 0;
        m_poller->modEvent(sock->getFD(), flag | EventPoller::Event::ERROR);
#endif
    }

    void Socket::enableWrite(const SocketFD::ptr &sock) { // only called by other thread. Never use
        if (m_write_enable) {
            return;
        }
        m_write_enable = true;
#if 0
        m_write_triggered = false;
        m_poller->modEvent(sock->getFD(), EventPoller::Event::READ | EventPoller::Event::WRITE | EventPoller::Event::ERROR);
#endif
    }

    void Socket::disableWrite(const SocketFD::ptr &sock) {
#if 0
        if (m_write_enable == false) {
            return;
        }
        m_write_enable = false;
#endif
#if 0
        m_write_triggered = true;
        int flag = 0;
        m_poller->modEvent(sock->getFD(), flag | EventPoller::Event::ERROR);
#endif
    }

    ssize_t Socket::onRead(const SocketFD::ptr &sock, bool is_udp) noexcept {
        ssize_t ret = 0, nread = 0;
        int fd = sock->getFD();
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);

        while (m_read_enable) {
            do {
                std::vector<iovec> iovs = m_read_buffer->writeBuffers(32 * 1024);
                nread = recvFrom(fd, &iovs[0], iovs.size(), &addr, len);
            } while (-1 == nread && UV_EINTR == get_uv_error(true));
            if (nread <= 0) {
                setReadTriggered(false);
                if (nread < 0) {
                    auto err = get_uv_error(true);
                    if (err != UV_EAGAIN) {
                        if (!is_udp) {
                            emitErr(toSocketException(err));
                        } else {
                            HAMMER_LOG_WARN(g_logger) << "Recv err on udp socket: " << fd << uv_strerror(err);
                        }
                    }
                    return ret;
                }
                if (nread == 0) {
                    if (!is_udp) {
                        emitErr(SocketException(ERRCode::EEOF, "end of file..."));
                    } else {
                        HAMMER_LOG_WARN(g_logger) << "Recv eof on udp socket: " << fd;
                    }
                    return ret;
                }
            }

            ret += nread;
            m_read_buffer->product(nread);

            LOCK_GUARD(m_event_cb_mutex);
            try {
                m_on_read_cb(m_read_buffer, (struct sockaddr*)&addr, len);
                // assert upper consume over TODO
            } catch (std::exception &e) {
                HAMMER_LOG_WARN(g_logger) << "Exception occurred when emit on_read_cb: " << e.what();
            }
        }
        return 0;
    }

    void Socket::onWritten(const SocketFD::ptr &sock) {
        bool flag;
        {
            LOCK_GUARD(m_event_cb_mutex);
            flag = m_on_written_cb();
        }
        if (!flag) {
            setOnWrittenCB(nullptr);
        }
    }

    bool Socket::writeData(const SocketFD::ptr &sock) {
        MBuffer::ptr tmp_buffer = std::make_shared<MBuffer>();
        {
            LOCK_GUARD(m_write_buffer_sending_mutex);
            if (m_write_buffer_sending->readAvailable()) {
                m_write_buffer_sending.swap(tmp_buffer);
            }
        }
        if (tmp_buffer->readAvailable() == 0) {
            do {
                {
                    LOCK_GUARD(m_write_buffer_waiting_mutex);
                    if (m_write_buffer_waiting->readAvailable()) {
                        LOCK_GUARD(m_event_cb_mutex);
#if 0
                        tmp_buffer = std::move(m_write_buffer_waiting);
#else
                        tmp_buffer->copyIn(*m_write_buffer_waiting.get());
                        m_write_buffer_waiting->clear();
#endif
                        break;
                    }
                }
                // all data consumed done
                onWritten(sock);
                return true;
            } while (0);
        }
        int fd = sock->getFD();
        bool is_udp = sock->getType() == SocketFD::SocketType::UDP;
        if (tmp_buffer->readAvailable()) {
            std::vector<iovec> iovs = tmp_buffer->readBuffers();
            int ret = sendTo(fd, &iovs[0], iovs.size());
            if (ret > 0) {
                if ((size_t)ret < tmp_buffer->readAvailable()) {
                    setWriteTriggered(false);
                }
                tmp_buffer->consume(ret);
            } else {
                setWriteTriggered(false);
                if (get_uv_error(true) != UV_EAGAIN) {
                    if (is_udp) {
                        tmp_buffer->consume(tmp_buffer->readAvailable());
                    }
                    emitErr(toSocketException(get_uv_error(true)));
                    return false;
                }
            }
        }
        if (tmp_buffer->readAvailable()) {
            LOCK_GUARD(m_write_buffer_sending_mutex);
            tmp_buffer.swap(m_write_buffer_sending);
            m_write_buffer_sending->copyIn(*tmp_buffer.get(), tmp_buffer->readAvailable());
            return true;
        }
        return writeData(sock);
    }

    void Socket::onWrite(const SocketFD::ptr &sock) {
        bool empty_waiting;
        bool empty_sending;
        {
            LOCK_GUARD(m_write_buffer_waiting_mutex);
            empty_waiting = m_write_buffer_waiting->readAvailable() == 0;
        }
        {
            LOCK_GUARD(m_write_buffer_sending_mutex);
            empty_sending = m_write_buffer_sending->readAvailable() == 0;
        }
        if (empty_sending && empty_waiting) {
            disableWrite(sock);
        } else {
            writeData(sock);
        }
    }

    bool Socket::attachEvent(const SocketFD::ptr &sock) {
        //std::weak_ptr<Socket> weak_self = shared_from_this();
        std::weak_ptr<Socket> weak_self = std::dynamic_pointer_cast<Socket>(shared_from_this());
        std::weak_ptr<SocketFD> weak_sock = sock;
        m_read_enable = true;
        m_read_buffer = m_poller->getSharedBuffer();
        auto is_udp = sock->getType() == SocketFD::SocketType::UDP;
        int fd = sock->getFD();
        Socket *sock_addr = this;
        int ret = m_poller->addEvent(sock->getFD(), EventPoller::Event::READ | EventPoller::Event::WRITE | EventPoller::Event::ERROR,
                [weak_self, weak_sock, is_udp, fd, sock_addr](int event) {
            auto strong_self = weak_self.lock();
            auto strong_sock = weak_sock.lock();
            if (!strong_self || !strong_sock) {
                if (strong_self == nullptr && strong_sock == nullptr) {
                    HAMMER_LOG_WARN(g_logger) << "attachEvent both nullptr fd: " << fd << ", sock_addr: " << sock_addr;
                    sleep(5);
                    HAMMER_ASSERT(0);
                } else {
                    if (strong_self == nullptr) {
                        HAMMER_LOG_WARN(g_logger) << "attachEvent strong_self nullptr fd: " << fd;
                    }
                    if (strong_sock == nullptr) {
                        HAMMER_LOG_WARN(g_logger) << "attachEvent strong_sock nullptr fd: " << fd;
                    }
                }
                return;
            }
            if (event & EventPoller::Event::READ) {
                HAMMER_LOG_DEBUG(g_logger) << "attachEvent socket onRead: " << strong_sock->getFD();
                strong_self->setReadTriggered(true);
                strong_self->onRead(strong_sock, is_udp);
            }
            if (event & EventPoller::Event::WRITE) {
                HAMMER_LOG_DEBUG(g_logger) << "attachEvent socket onWrite: " << strong_sock->getFD();
                strong_self->setWriteTriggered(true);
                strong_self->onWrite(strong_sock);
            }
            if (event & EventPoller::Event::ERROR) {
                strong_self->setReadTriggered(true);
                strong_self->setWriteTriggered(true);
                HAMMER_LOG_WARN(g_logger) << "attachEvent socket onErr: " << strong_sock->getFD();
                strong_self->emitErr(getSocketError(strong_sock));
            }
        });
        return -1 != ret;
    }

    bool Socket::listen(const SocketFD::ptr &sock) {
        closeSocket();
        std::weak_ptr<SocketFD> weak_sock = sock;
        std::weak_ptr<Socket>   weak_self = shared_from_this();
        m_read_enable = true;
        int ret = m_poller->addEvent(sock->getFD(), EventPoller::Event::READ | EventPoller::Event::ERROR,
                [weak_sock, weak_self](int event) {
            auto strong_self = weak_self.lock();
            auto strong_sock = weak_sock.lock();
            if (!strong_self || !strong_sock) {
                return;
            }
            strong_self->onAccept(strong_sock, event);
        });
        if (ret == -1) {
            return false;
        }
        LOCK_GUARD(m_socketFD_mutex);
        m_fd = sock;
        return true;
    }

    bool Socket::listen(uint16_t port, const std::string& local_ip, int backlog) {
        int sock = SocketOps::listen(port, local_ip.data(), backlog);
        if (sock == -1) {
            return false;
        }
        return listen(std::make_shared<SocketFD>(sock, SocketFD::SocketType::TCP, m_poller));
    }

    int Socket::onAccept(const SocketFD::ptr &sock, int event) {
        int fd;
        while (1) {
            if (event & EventPoller::Event::READ) {
                do {
                    fd = (int)accept(sock->getFD(), nullptr, nullptr);
                } while (-1 == fd && UV_EINTR == get_uv_error(true));

                if (fd == -1) {
                    int err = get_uv_error(true);
                    if (err == UV_EAGAIN) {
                        return 0;
                    }
                    auto e = toSocketException(err);
                    emitErr(e);
                    HAMMER_LOG_WARN(g_logger) << "Accept socket failed: " << e.what();
                    return -1;
                }
                SocketOps::setNoSigpipe(fd);
                SocketOps::setNoBlocked(fd);
                SocketOps::setNoDelay(fd);
                SocketOps::setSendBuf(fd);
                SocketOps::setRecvBuf(fd);
                SocketOps::setCloseWait(fd);
                SocketOps::setCloExec(fd);

                Socket* new_sock = nullptr;
                try {
                    LOCK_GUARD(m_event_cb_mutex);
                    new_sock = m_on_before_accept_cb(m_poller);
                } catch (std::exception &e) {
                    HAMMER_LOG_WARN(g_logger) << "Exception occurred when on_before_accept: " << e.what();
                    close(fd);
                    continue;
                }
                if (!new_sock) {
                    new_sock = Socket::createSocketPtr(m_poller, false);
                }
                new_sock->setSocketFD(fd);
                try {
                    LOCK_GUARD(m_event_cb_mutex);
                    m_on_accept_cb(new_sock);
                } catch (std::exception &e) {
                    HAMMER_LOG_WARN(g_logger) << "Exception occurred when emit onAccept: " << e.what();
                    continue;
                }
            }
            if (event & EventPoller::Event::ERROR) {
                auto e = getSocketError(sock);
                emitErr(e);
                HAMMER_LOG_WARN(g_logger) << "TCP listener occurred a err: " << e.what();
                return -1;
            }
        }
    }

    void Socket::onConnected(const SocketFD::ptr &sock, const onErrCB &cb) {
        auto err = getSocketError(sock, false);
        if (err) {
            cb(err);
            return;
        }
        getPoller()->delEvent(sock->getFD()); // ?
        if (!attachEvent(sock)) {
            cb(SocketException(ERRCode::OTHER, "add event to poller failed when connected"));
            return;
        }
        cb(err);
    }

    void Socket::connect(const std::string &url, uint16_t port, const onErrCB &err_cb, float timeout,
                 const std::string &local_ip, uint16_t local_port) {
        closeSocket();
        std::weak_ptr<Socket> weak_self = shared_from_this();
        auto conn_cb = [err_cb, weak_self](const SocketException &err) {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return;
            }
            strong_self->m_conn_cb = nullptr;
            strong_self->m_conn_timer = nullptr;
            if (err) {
                LOCK_GUARD(strong_self->m_socketFD_mutex);
                strong_self->m_fd = nullptr;
            }
            err_cb(err);
        };

        auto async_conn_cb = std::make_shared<std::function<void(int)>>([weak_self, err_cb](int sock) {
            auto strong_self = weak_self.lock();
            if (sock == -1 || !strong_self) {
                if (!strong_self) {
                    if (sock >= 0) {
                        close(sock);
                    }
                } else {
                    err_cb(SocketException(ERRCode::DNS, get_uv_errmsg(true)));
                }
                return;
            }
            auto strong_sock = std::make_shared<SocketFD>(sock, SocketFD::SocketType::TCP,
                    strong_self->getPoller());
            std::weak_ptr<SocketFD> weak_sock = strong_sock;
            int ret = strong_self->getPoller()->addEvent(sock, EventPoller::Event::WRITE,
                    [weak_self, weak_sock, err_cb](int event) {
                auto strong_self = weak_self.lock();
                auto strong_sock = weak_sock.lock();
                if (strong_self && strong_sock) {
                    strong_self->onConnected(strong_sock, err_cb);
                }
            });
            if (ret == -1) {
                err_cb(SocketException(ERRCode::OTHER, "add event to poller failed when start connect"));
                return;
            }
            LOCK_GUARD(strong_self->getFdMutex());
            strong_self->setSockFD(strong_sock);
        });

        if (SocketOps::is_ipv4(url.c_str()) ||
                SocketOps::is_ipv6(url.c_str())) {
            (*async_conn_cb)(SocketOps::connect(url.data(), port, true, local_ip.data(), local_port));
        } else {
            auto poller = m_poller;
            std::weak_ptr<std::function<void(int)>> weak_task = async_conn_cb;
            Singleton<WorkThreadPool>::instance().getExecutor()->async([url, port, local_ip, local_port, weak_task, poller]() {
                int sock = SocketOps::connect(url.data(), port, true, local_ip.data(), local_port);
                poller->async([sock, weak_task]() {
                    auto strong_task = weak_task.lock();
                    if (strong_task) {
                        (*strong_task)(sock);
                    } else {
                        close(sock);
                    }
                });
            });
            m_conn_cb = async_conn_cb;
        }

        m_conn_timer = std::make_shared<Timer>(timeout, [weak_self, err_cb]()->bool {
            err_cb(SocketException(ERRCode::TIMEOUT, uv_strerror(UV_ETIMEDOUT)));
            return false;
        }, m_poller);
    }

    int Socket::flushAll() {
        return 0;
    }

    ssize_t Socket::send_l(MBuffer::ptr buf) {
        auto size = buf ? buf->readAvailable() : 0;
        if (!size) {
            return 0;
        }
        {
            LOCK_GUARD(m_write_buffer_waiting_mutex);
            m_write_buffer_waiting->copyIn(*buf.get());
            buf->clear();
        }
        // 同步写
        {
            if (isWriteTriggered()) {
                return writeData(m_fd) ? size : 0; 
            }
            // 超时处理
        }
        return size;
    }

    ssize_t Socket::send(const char *buf, size_t size, struct sockaddr *addr, socklen_t addr_len) {
        if (size <= 0) {
            size = strlen(buf);
            if (!size) {
                return 0;
            }
        }
        auto buffer = std::make_shared<MBuffer>();
        buffer->copyIn(buf);
        return send(buffer, addr, addr_len);
    }

    ssize_t Socket::send(std::string buf, struct sockaddr *addr, socklen_t addr_len) {
        auto buffer = std::make_shared<MBuffer>();
        buffer->copyIn(buf);
        return send(buffer, addr, addr_len);
    }

    ssize_t Socket::send(MBuffer::ptr buf, struct sockaddr *addr, socklen_t addr_len) {
        return send_l(buf);
    }

    void Socket::setOnWrittenCB(onWrittenCB cb) {
        LOCK_GUARD(m_event_cb_mutex);
        if (cb) {
            m_on_written_cb = std::move(cb);
        } else {
            m_on_written_cb = []() {return true; };
        }
    }

    void Socket::setOnBeforeAcceptCB(onCreateSocketCB cb) {
        LOCK_GUARD(m_event_cb_mutex);
        if (cb) {
            m_on_before_accept_cb = std::move(cb);
        } else {
            m_on_before_accept_cb = [](const EventPoller::ptr &poller) {
                return nullptr;
            };
        }
    }

    void Socket::setOnAcceptCB(onAcceptCB cb) {
        LOCK_GUARD(m_event_cb_mutex);
        if (cb) {
            m_on_accept_cb = std::move(cb);
        } else {
            m_on_accept_cb = [](Socket *sock) {
                HAMMER_LOG_WARN(g_logger) << "Socket not set accept cb";
            };
        }
    }

    void Socket::setOnReadCB(onReadCB cb) {
        LOCK_GUARD(m_event_cb_mutex);
        if (cb) {
            m_on_read_cb = std::move(cb);
        } else {
            m_on_read_cb = [](const MBuffer::ptr &, struct sockaddr *, int) {
                HAMMER_LOG_WARN(g_logger) << "Socket not set read cb";
            };
        }
    }

    void Socket::setOnErrCB(onErrCB cb) {
        LOCK_GUARD(m_event_cb_mutex);
        if (cb) {
            m_on_err_cb = std::move(cb);
        } else {
            m_on_err_cb = [](const SocketException &err) {
                HAMMER_LOG_WARN(g_logger) << "Socket not set err cb, err: " << err.what();
            };
        }

    }

    SocketFD::ptr Socket::cloneSocketFD(const Socket &other) {
        SocketFD::ptr sock;
        {
            LOCK_GUARD(other.m_socketFD_mutex);
            if (!other.m_fd) {
                HAMMER_LOG_WARN(g_logger) << "SocketFD is nullptr";
                return nullptr;
            }
            sock = std::make_shared<SocketFD>(*(other.m_fd), m_poller);
        }
        return sock;
    }

    bool Socket::cloneFromListenSocket(const Socket &other) {
        auto sock = cloneSocketFD(other);
        if (!sock) {
            return false;
        }
        return listen(sock);
    }

}
