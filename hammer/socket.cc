//
// Created by root on 12/6/22.
//

#include <sys/socket.h>
#include "socket.hh"
#include "log.hh"
#include "uv_errno.hh"
#include "socket_ops.hh"

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

    Socket::Socket(const EventPoller::ptr poller, bool enable_mutex)
            : m_poller(poller), m_socketFD_mutex(enable_mutex),
            m_event_cb_mutex(enable_mutex),
            m_write_buffer_waiting_mutex(enable_mutex),
            m_write_buffer_sending_mutex(enable_mutex) {
        if (!poller) {
            // TODO
        }
    }

    void Socket::closeSocket() {
        m_conn_timer = nullptr;
        m_conn_cb = nullptr;

        LOCK_GUARD(m_socketFD_mutex);
        m_fd = nullptr;
    }

    Socket::~Socket() {
        closeSocket();
    }

    Socket::ptr Socket::createSocket(const EventPoller::ptr &poller, bool enable_mutex) {
        return std::make_shared<Socket>(poller, enable_mutex);
    }

    SocketFD::ptr Socket::setSocketFD(int fd) {
        closeSocket();
        auto socket = std::make_shared<SocketFD>(fd, SocketFD::SocketType::TCP, m_poller);
        LOCK_GUARD(m_socketFD_mutex);
        m_fd = socket;
        return socket;
    }

    static ssize_t recvFrom(int fd, void* buffer, size_t length, struct sockaddr_storage &addr, socklen_t len, int flags = 0) {
        return ::recvfrom(fd, buffer, length, flags, (sockaddr*)&addr, &len);
    }

    static ssize_t recvFrom(int fd, iovec* buffers, size_t length, struct sockaddr_storage &addr, socklen_t len, int flags = 0) {
        msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = (iovec*)buffers;
        msg.msg_iovlen = length;
        msg.msg_name = (void*)&addr;
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
        // TODO
        return true;
    }

    void Socket::stopWriteAbleEvent(const SocketFD::ptr &sock) {
        // TODO
    }

    ssize_t Socket::onRead(const SocketFD::ptr &sock, bool is_udp) noexcept {
        ssize_t ret = 0, nread = 0;
        int fd = sock->getFD();
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);

        while (m_enable_recv) {
            do {
                std::vector<iovec> iovs = m_read_buffer->writeBuffers(32 * 1024);
                nread = recvFrom(fd, &iovs[0], iovs.size(), addr, len);
            } while (-1 == nread && UV_EINTR == get_uv_error(true));
            if (nread == 0) {
                if (!is_udp) {
                    emitErr(SocketException(ERRCode::EEOF, "end of file..."));
                } else {
                    HAMMER_LOG_WARN(g_logger) << "Recv eof on udp socket: " << fd;
                }
                return ret;
            }
            if (nread == -1) {
                auto err = get_uv_error(true);
                if (err != UV_EAGAIN) {
                    if (!is_udp) {
                        emitErr(toSocketException(err));
                    } else {
                        HAMMER_LOG_WARN(g_logger) << "Recv err on udp socket: " << fd << uv_strerror(err);
                    }
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

    bool Socket::writeData(const SocketFD::ptr &sock, bool poller_thread) {
        MBuffer::ptr tmp_buffer = nullptr;
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
                        tmp_buffer = std::move(m_write_buffer_waiting);
                        break;
                    }
                }
                if (poller_thread) {
                    // TODO
                }
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
                    if (!poller_thread) {
                        // TODO
                    }
                }
                tmp_buffer->consume(ret);
            } else if (ret < 0) {
                if (get_uv_error(true) == UV_EAGAIN) {
                    if (!poller_thread) {
                        // TODO
                    }
                }
            } else {
                if (is_udp) {
                    tmp_buffer->consume(tmp_buffer->readAvailable());
                }
                // emitErr
                return false;
            }
        }
        if (tmp_buffer->readAvailable()) {
            LOCK_GUARD(m_write_buffer_sending_mutex);
            tmp_buffer.swap(m_write_buffer_sending);
            m_write_buffer_sending->copyIn(*tmp_buffer.get(), tmp_buffer->readAvailable());
            return true;
        }
        return poller_thread ? writeData(sock, poller_thread) : true;
    }

    void Socket::onWriteAble(const SocketFD::ptr &sock) {
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
            stopWriteAbleEvent(sock);
        } else {
            writeData(sock, true);
        }
    }

    bool Socket::attachEvent(const SocketFD::ptr &sock) {
        std::weak_ptr<Socket> weak_self = shared_from_this();
        std::weak_ptr<SocketFD> weak_sock = sock;
        m_enable_recv = true;
        m_read_buffer = m_poller->getSharedBuffer();
        auto is_udp = sock->getType() == SocketFD::SocketType::UDP;
        int ret = m_poller->addEvent(sock->getFD(), EventPoller::Event::READ | EventPoller::Event::WRITE | EventPoller::Event::ERROR,
                [weak_self, weak_sock, is_udp](int event) {
            auto strong_self = weak_self.lock();
            auto strong_sock = weak_sock.lock();
            if (!strong_self || !strong_sock) {
                return;
            }
            if (event & EventPoller::Event::READ) {
                strong_self->onRead(strong_sock, is_udp);
            }
            if (event & EventPoller::Event::WRITE) {
                strong_self->onWriteAble(strong_sock);
            }
            if (event & EventPoller::Event::ERROR) {
                strong_self->emitErr(getSocketError(strong_sock));
            }
        });
        return -1 != ret;
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
                Socket::ptr new_sock;
                try {
                    LOCK_GUARD(m_event_cb_mutex);
                    new_sock = m_on_before_accept_cb(m_poller);
                } catch (std::exception &e) {   
                    HAMMER_LOG_WARN(g_logger) << "Exception occurred when on_before_accept: " << e.what();
                    close(fd);
                    continue;
                }
                if (!new_sock) {
                    new_sock = Socket::createSocket(m_poller, false);
                }
                auto new_sock_fd = new_sock->setSocketFD(fd);
                std::shared_ptr<void> completed(nullptr, [new_sock, new_sock_fd](void *) {
                    try {
                        if (!new_sock->attachEvent(new_sock_fd)) {
                            new_sock->emitErr(SocketException(ERRCode::EEOF, "add event to poller failed when accept a new socket"));
                        }
                    } catch (std::exception &e) {
                        HAMMER_LOG_WARN(g_logger) << "Exception occurred : " << e.what();
                    }
                });
                try {
                    LOCK_GUARD(m_event_cb_mutex);
                    m_on_accept_cb(new_sock, completed);
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

}
