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
        using onReadCB = std::function<void(const MBuffer::ptr &, struct sockaddr *, int addr_len)>;

        explicit TcpServer(const EventPoller::ptr &poller = nullptr);
        virtual ~TcpServer();

        void start(uint16_t port, const std::string &host = "::", uint32_t backlog = 1024);

        void setOnRead(Socket::onReadCB cb) { m_on_read_socket = std::move(cb); }
        void setOnWrittenCB(Socket::onWrittenCB cb) { m_on_written_socket = std::move(cb); }
        void setOnErr(Socket::onErrCB cb) { m_on_err_socket = std::move(cb); }

    protected:
        virtual Socket::ptr onBeforeAcceptConnection(const EventPoller::ptr &poller);
        virtual void onAcceptConnection(const Socket::ptr &sock);

        virtual TcpServer::ptr onCreateServer(const EventPoller::ptr &poller);
        virtual void cloneFrom(const TcpServer &that);
    private:
        Socket::ptr createSocket(const EventPoller::ptr &poller);
        void inactivityCop();
        ptr getServer(const EventPoller *poller) const;
    private:
        EventPoller::ptr    m_poller = nullptr;
        Socket::ptr         m_socket = nullptr;
        Timer::ptr          m_timer = nullptr;
        std::unordered_map<Socket *, Socket::ptr> m_tcp_conns;
        Socket::onCreateSocketCB m_on_create_socket = nullptr;
        Socket::onReadCB    m_on_read_socket = nullptr;
        Socket::onWrittenCB m_on_written_socket = nullptr;
        Socket::onErrCB     m_on_err_socket = nullptr;
        const TcpServer     *m_parent = nullptr;
        std::unordered_map<const EventPoller *, ptr> m_cloned_server;
    };

}


#endif //HAMMER_TCP_SERVER_HH
