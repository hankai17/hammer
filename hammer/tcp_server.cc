//
// Created by root on 12/16/22.
//

#include "tcp_server.hh"
#include "util.hh"
#include "log.hh"
#include "socket_ops.hh"

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");
    static std::atomic<uint64_t> g_session_index{0};

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

    static void defaultErrCB(const SocketException &e) {
        HAMMER_LOG_WARN(g_logger) << "defaultErrCB err: " << e.what();
        return;
    }

    Session::Session(const std::weak_ptr<TcpServer> &server, const Socket::ptr &sock) 
        : m_socket(sock), m_server(server) {
        m_id = getID();
    }

    ssize_t Session::send(MBuffer::ptr buf) {
        return m_socket->send(std::move(buf));
    }

    std::string Session::getID() const {
        if (m_id.empty()) {
            m_id = std::to_string(++g_session_index) + '-' 
                    + std::to_string(m_socket->getFD());
        }
        return m_id;
    }

    void Session::shutdown(const SocketException &e) {
        m_socket->emitErr(e);
    }

    void Session::safeShutdown() {
        /*
        std::weak_ptr<Session> weak_self = shared_from_this();
        async_first([weak_self]() {
            auto strong_self = weak_self.lock();
            if (strong_self) {
                strong_self->shutdown();
            }
        });
        */
    }

    Session::ptr SessionManager::get(const std::string &key) {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_sessions.find(key);
        if (it == m_sessions.end()) {
            return nullptr;
        }
        return it->second.lock();
    }

    void SessionManager::foreach(const sessionCB &cb) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_sessions.begin(); it != m_sessions.end();) {
            auto session = it->second.lock();
            if (!session) {
                m_sessions.erase(it++);
                continue;
            }
            cb(it->first, session); 
            ++it;
        } 
    }

    bool SessionManager::add(const std::string &key, const Session::ptr &session) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.emplace(key, session).second;
    }

    bool SessionManager::del(const std::string &key) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_sessions.erase(key);
    }

    TcpServer::TcpServer(const EventPoller::ptr &poller) :
            m_poller(poller) {
        m_on_create_socket = [](const EventPoller::ptr &poller) {
           return Socket::createSocketPtr(poller, false);
        };
        m_socket = Socket::createSocket(poller);
        m_socket->setOnBeforeAcceptCB([this](const EventPoller::ptr &poller) {
            return onBeforeAcceptConnection(poller);
        });
        m_socket->setOnAcceptCB([this](Socket* sock) {
            auto poller = sock->getPoller().get();
            auto server = getServer(poller);
            poller->async([server, sock]() {
                Socket::ptr sock_ptr(sock);
                server->onAcceptConnection(sock_ptr);
                try {
                    if (!sock->attachEvent(sock->getSockFD())) {
                        sock->emitErr(SocketException(ERRCode::EEOF, "add event to poller failed when accept a new socket"));
                    }
                } catch (std::exception &e) {
                    HAMMER_LOG_WARN(g_logger) << "Exception occurred : " << e.what();
                }
            });
        });
    }

    Socket* TcpServer::createSocket(const EventPoller::ptr &poller) {
        return m_on_create_socket(poller);
    }

    Socket* TcpServer::onBeforeAcceptConnection(const EventPoller::ptr &poller) {
        HAMMER_ASSERT(poller->isCurrentThread());
        //return nullptr;
        return createSocket(Singleton<EventPollerPool>::instance().getPoller(false));
    }

    void TcpServer::onAcceptConnection(const Socket::ptr &sock) {
        std::weak_ptr<TcpServer> weak_self = std::dynamic_pointer_cast<TcpServer>(shared_from_this());
        auto session = m_session_alloc_cb(std::dynamic_pointer_cast<TcpServer>(shared_from_this()), sock);
        auto success = m_sessions.emplace(session.get(), session).second;

        HAMMER_ASSERT(success = true);
        HAMMER_ASSERT(m_poller->isCurrentThread());

        std::weak_ptr<Session> weak_session = session;
        sock->setOnReadCB([weak_session](const MBuffer::ptr &buf, struct sockaddr *, int) {
            auto strong_session = weak_session.lock();
            if (!strong_session) {
                return;
            }
            try {
                strong_session->onRecv(buf);
            } catch (SocketException &e) {
                strong_session->shutdown(e);
            } catch (std::exception &e) {
                strong_session->shutdown(SocketException(ERRCode::SHUTDOWN, e.what()));
            }
        });
        auto session_ptr = session.get();
        sock->setOnErrCB([weak_self, weak_session, session_ptr](const SocketException &e) {
            OnceToken token(nullptr, [&]() {
                auto strong_self = weak_self.lock();
                if (!strong_self) {
                    return;
                }
                HAMMER_ASSERT(strong_self->m_poller->isCurrentThread());
                strong_self->m_sessions.erase(session_ptr);
            });
            auto strong_session = weak_session.lock();
            if (strong_session) {
                strong_session->onError(e);
            }
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
        HAMMER_ASSERT(0);
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

    std::string TcpServer::toString() {
        std::stringstream ss;
#if 0
        for (auto &it : m_tcp_conns) {
            ss << "<fd: " << it.second->getFD()
               << ", use_count: " << it.second.use_count() 
               << ", addr: " << it.second.get() << ", addrf: " << it.first
               << ">, ";
        }
#endif
        return ss.str();
    }

    void TcpServer::start_internal(uint16_t port, const std::string &host, uint32_t backlog) {
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
        Singleton<EventPollerPool>::instance().foreach([&](const TaskExecutor::ptr &executor) {
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
