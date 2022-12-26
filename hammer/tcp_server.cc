//
// Created by root on 12/16/22.
//

#include "tcp_server.hh"
#include "util.hh"
#include "log.hh"
#include "socket_ops.hh"

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");

    static void defaultReadCB(const MBuffer::ptr &buf, 
            struct sockaddr *addr, int addr_len) {
        HAMMER_LOG_WARN(g_logger) << "defaultReadCB, MBuffer len: " << buf->readAvailable();
        if (buf->readAvailable()) {
            buf->clear();
        }
        return;
    }

    static bool defaultWrittenCB() {
        HAMMER_LOG_WARN(g_logger) << "defaultWrittenCB: written done";
        return true;
    }

    static void defaultErrCB(const SocketException & e) {
        HAMMER_LOG_WARN(g_logger) << "defaultErrCB err: " << e.what();
        return;
    }

    TcpServer::TcpServer(const EventPoller::ptr &poller) :
            m_poller(poller) {
        m_on_create_socket = [](const EventPoller::ptr &poller) {
           return Socket::createSocket(poller, false);
        };
        m_socket = createSocket(poller);
        m_socket->setOnBeforeAccept([this](const EventPoller::ptr &poller) {
            return onBeforeAcceptConnection(poller);
        });
        m_socket->setOnAccept([this](Socket::ptr &sock, std::shared_ptr<void>& complete) {
            HAMMER_LOG_DEBUG(g_logger) << "onAccept: " << sock->getFD();
            auto poller = sock->getPoller().get();
            auto server = getServer(poller);
            poller->async([server, sock, complete]() {
                server->onAcceptConnection(sock);
            });
        });
    }

    Socket::ptr TcpServer::createSocket(const EventPoller::ptr &poller) {
        return m_on_create_socket(poller);
    }

    Socket::ptr TcpServer::onBeforeAcceptConnection(const EventPoller::ptr &poller) {
        HAMMER_ASSERT(poller->isCurrentThread());
        return nullptr;
        //return createSocket(Singleton<EventPollerPool>::instance().getPoller(false));
    }

    void TcpServer::onAcceptConnection(const Socket::ptr &sock) {
        std::weak_ptr<TcpServer> weak_self = std::dynamic_pointer_cast<TcpServer>(shared_from_this());
        std::weak_ptr<Socket> weak_sock = sock;
        auto sock_ptr = sock.get();
        auto success = m_tcp_conns.emplace(sock_ptr, sock).second;
        HAMMER_ASSERT(success = true);

        HAMMER_LOG_DEBUG(g_logger) << "1onAcceptConnection setCB: " << sock->getFD();
        //sock->setOnRead(m_on_read_socket == nullptr ? defaultReadCB : m_on_read_socket);
        sock->setOnRead([weak_self, weak_sock](const MBuffer::ptr &buf, struct sockaddr *addr, int addr_len) {
            if (buf->readAvailable()) {
                buf->clear();
            }
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return;
            }
            HAMMER_ASSERT(strong_self->m_poller->isCurrentThread());

            std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world";
            auto strong_sock = weak_sock.lock();
            if (!strong_sock) {
                return;
            }
            strong_sock->send(resp);
        });
        sock->setOnWritten([weak_self, sock_ptr]()->bool {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return false;
            }
            HAMMER_ASSERT(strong_self->m_poller->isCurrentThread());
            HAMMER_LOG_DEBUG(g_logger) << "onWritten erase fd: " << sock_ptr->getFD();
            strong_self->m_tcp_conns.erase(sock_ptr);
            return true;
        });
        sock->setOnErr([weak_self, weak_sock, sock_ptr](const SocketException &e) {
            OnceToken token(nullptr, [&]() {
                auto strong_self = weak_self.lock();
                if (!strong_self) {
                    return;
                }
                HAMMER_ASSERT(strong_self->m_poller->isCurrentThread());
                strong_self->m_tcp_conns.erase(sock_ptr);
            });
            /*
            auto sock = weak_sock.lock();
            if (sock) {
                //sock->
            }
            */
        });
        return;
    }

    TcpServer::ptr TcpServer::onCreateServer(const EventPoller::ptr &poller) {
        return std::make_shared<TcpServer>(poller);
    }

    void TcpServer::cloneFrom(const TcpServer &that) {
        if (!that.m_socket) {
            throw std::invalid_argument("TcpServer::cloneFrom other with null socket");
        }
        m_on_create_socket = that.m_on_create_socket;
        m_socket->cloneFromListenSocket(*(that.m_socket));
        std::weak_ptr<TcpServer> weak_self = std::dynamic_pointer_cast<TcpServer>(shared_from_this());
        m_timer = std::make_shared<Timer>(2.0f, [weak_self]()->bool {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return false;
            }
            strong_self->inactivityCop();
            return true;
        }, m_poller);
        m_parent = &that;
    }

    TcpServer::~TcpServer() {

    }

    void TcpServer::inactivityCop() {
        HAMMER_ASSERT(m_poller->isCurrentThread());
        /*
        for (auto &it : m_tcp_conns) {
        }
        */
    }

    TcpServer::ptr TcpServer::getServer(const EventPoller *poller) const {
        auto &ref = m_parent ? m_parent->m_cloned_server : m_cloned_server;
        auto it = ref.find(poller);
        if (it != ref.end()) {
            return it->second;
        }
        return std::static_pointer_cast<TcpServer>(m_parent ? const_cast<TcpServer*>(m_parent)->shared_from_this() :
                                              const_cast<TcpServer*>(this)->shared_from_this());
    }

    void TcpServer::start(uint16_t port, const std::string &host, uint32_t backlog) {
        if (!m_socket->listen(port, host.c_str(), backlog)) {
            throw std::runtime_error("listen failed");
        }
        std::weak_ptr<TcpServer> weak_self = std::dynamic_pointer_cast<TcpServer>(shared_from_this());
        m_timer = std::make_shared<Timer>(2.0f, [weak_self]()->bool {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return false;
            }
            strong_self->inactivityCop();
            return true;
        }, m_poller);
        Singleton<EventPollerPool>::instance().for_each([&](const TaskExecutor::ptr &executor) {
            EventPoller::ptr poller = std::dynamic_pointer_cast<EventPoller>(executor);
            if (poller == m_poller || !poller) {
                return;
            }
            auto server = onCreateServer(poller);
            m_cloned_server[poller.get()] = server;
            server->cloneFrom(*this);
        });
    }

}
