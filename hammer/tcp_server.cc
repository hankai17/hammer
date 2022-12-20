//
// Created by root on 12/16/22.
//

#include "tcp_server.hh"
#include "util.hh"
#include "log.hh"

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");

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
            TcpServer::ptr server = shared_from_this();
            sock->getPoller()->async([server, sock, complete]() { // 先执行task 最后析构list 析构complete(sock-- sockfd--) 析构sock(sock-- sockfd--调用close)
                server->onAcceptConnection(sock);
            });
        });
    }

    Socket::ptr TcpServer::createSocket(const EventPoller::ptr &poller) {
        return m_on_create_socket(poller);
    }

    Socket::ptr TcpServer::onBeforeAcceptConnection(const EventPoller::ptr &poller) {
        HAMMER_ASSERT(poller->isCurrentThread());
        return createSocket(Singleton<EventPollerPool>::instance().getPoller(false));
    }

    void TcpServer::onAcceptConnection(const Socket::ptr &sock) {
        // reset socket's rwe cb
        HAMMER_LOG_WARN(g_logger) << "onAcceptConnection...sock.use: " << sock.use_count();
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
            server->cloneFrom(*this);
        });
    }

}
