//
// Created by root on 12/16/22.
//

#ifndef HAMMER_TCP_SERVER_HH
#define HAMMER_TCP_SERVER_HH

#include <memory>
#include <unordered_map>
#include "event_poller.hh"
#include "socket.hh"

namespace hammer {
    class TcpServer :
            public std::enable_shared_from_this<TcpServer> {
    public:
        using ptr = std::shared_ptr<TcpServer>;
        explicit TcpServer(const EventPoller::ptr &poller = nullptr);
        virtual ~TcpServer();

        void start(uint16_t port, const std::string &host = "::", uint32_t backlog = 1024);

    protected:
        virtual Socket::ptr onBeforeAcceptConnection(const EventPoller::ptr &poller);
        virtual void onAcceptConnection(const Socket::ptr &sock);

        virtual TcpServer::ptr onCreateServer(const EventPoller::ptr &poller);
        virtual void cloneFrom(const TcpServer &that);
    private:
        Socket::ptr createSocket(const EventPoller::ptr &poller);
        void inactivityCop();
    private:
        EventPoller::ptr    m_poller;
        Socket::ptr         m_socket;
        Timer::ptr          m_timer;
        std::unordered_map<Socket *, Socket::ptr> m_tcp_conns;
        Socket::onCreateSocketCB m_on_create_socket;

    };

}


#endif //HAMMER_TCP_SERVER_HH
