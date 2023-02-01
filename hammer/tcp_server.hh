//
// Created by root on 12/16/22.
//

#ifndef HAMMER_TCP_SERVER_HH
#define HAMMER_TCP_SERVER_HH

#include <string.h>
#include <memory>
#include <unordered_map>
#include "event_poller.hh"
#include "socket.hh"

namespace hammer {
    class TcpServer;

    class Session : public std::enable_shared_from_this<Session> {
    public:
        using ptr = std::shared_ptr<Session>;
        Session(const std::weak_ptr<TcpServer> &server, const Socket::ptr &sock);
        ~Session() = default;
 
        virtual void onRecv(const MBuffer::ptr &buf) {};
        virtual void onWritten() {};
        virtual void onError(const SocketException &e) {};
        virtual void onManager() {};

        ssize_t send(MBuffer::ptr buf);
        std::string getID() const;
        void shutdown(const SocketException &e);
        void safeShutdown();
    private:
        mutable std::string         m_id;
        Socket::ptr                 m_socket;
        std::weak_ptr<TcpServer>    m_server;
    };

    class SessionManager : public std::enable_shared_from_this<SessionManager> {
    public:
        using ptr = std::shared_ptr<SessionManager>;
        using sessionCB = std::function<void(const std::string &id, const Session::ptr &session)>;
        SessionManager() = default;
        ~SessionManager() = default;
        Session::ptr get(const std::string &key);
        void foreach(const sessionCB &cb);
    private:
        bool add(const std::string &key, const Session::ptr &session);
        bool del(const std::string &key);
    private:
        std::mutex          m_mutex;
        std::unordered_map<std::string, std::weak_ptr<Session>> m_sessions;
    };

    class TcpServer :
            public std::enable_shared_from_this<TcpServer> {
    public:
        using ptr = std::shared_ptr<TcpServer>;
        using sessionAlloc = std::function<Session::ptr(const TcpServer::ptr &, const Socket::ptr &)>;
        using onReadCB = std::function<void(const MBuffer::ptr &, struct sockaddr *, int addr_len)>;

        explicit TcpServer(const EventPoller::ptr &poller = nullptr);
        virtual ~TcpServer();

        void start_internal(uint16_t port, const std::string &host = "::", uint32_t backlog = 1024);
        template <typename SessionType>
        void start(uint16_t port, const std::string &host = "::", uint32_t backlog = 1024) {
            m_session_alloc_cb = [](const TcpServer::ptr &server, const Socket::ptr &sock) {
                auto session = std::make_shared<SessionType>(server, sock);
                //Singleton<SessionManager>::instance().add(session->getID(), session);
                return session;
            };
            start_internal(port, host, backlog);
        }

        void setOnReadCB(Socket::onReadCB cb) { m_on_read_socket = std::move(cb); }
        void setOnWrittenCB(Socket::onWrittenCB cb) { m_on_written_socket = std::move(cb); }
        void setOnErrCB(Socket::onErrCB cb) { m_on_err_socket = std::move(cb); }

    protected:
        virtual Socket* onBeforeAcceptConnection(const EventPoller::ptr &poller);
        virtual void onAcceptConnection(const Socket::ptr &sock);

        virtual TcpServer::ptr onCreateServer(const EventPoller::ptr &poller);
        virtual void cloneFrom(const TcpServer &that);
    private:
        Socket* createSocket(const EventPoller::ptr &poller);
        void inactivityCop();
        ptr getServer(const EventPoller *poller) const;
        std::string toString();
    private:
        EventPoller::ptr    m_poller = nullptr;
        Socket::ptr         m_socket = nullptr;
        Timer::ptr          m_timer = nullptr;
        sessionAlloc        m_session_alloc_cb = nullptr;
        std::unordered_map<Session *, Session::ptr> m_sessions;
        Socket::onCreateSocketCB m_on_create_socket = nullptr;
        Socket::onReadCB    m_on_read_socket = nullptr;
        Socket::onWrittenCB m_on_written_socket = nullptr;
        Socket::onErrCB     m_on_err_socket = nullptr;
        const TcpServer     *m_parent = nullptr;
        std::unordered_map<const EventPoller *, ptr> m_cloned_server;
    };

    class TcpClient : public std::enable_shared_from_this<TcpClient> {
    public:
        using ptr = std::shared_ptr<TcpClient>;
        TcpClient(const EventPoller::ptr &poller = nullptr);
        ~TcpClient();
        void startConnect(const std::string &url, uint16_t port, float timeout = 1000 * 5, uint16_t local_port = 0);
        void shutdown(const SocketException &e = SocketException(ERRCode::SHUTDOWN, "self shutdown"));
        bool alive() const;
        ssize_t send(MBuffer::ptr buf);
    protected:
        virtual void onConnect(const SocketException &e) {};
        virtual void onRecv(const MBuffer::ptr &buf) {};
        virtual void onWritten() {};
        virtual void onError(const SocketException &e) {};
        virtual void onManager() {};
    private:
        void onSocketConnect(const SocketException &e);

        EventPoller::ptr    m_poller = nullptr;
        Socket::ptr         m_socket = nullptr;
        Timer::ptr          m_timer = nullptr;
    };

    template <typename TcpClientType>
    class TcpClientWithSSL : public TcpClientType {
    public:
        using ptr = std::shared_ptr<TcpClientWithSSL>;
        template <typename ...ArgsType>
        TcpClientWithSSL(ArgsType &&...args) 
            : TcpClientType(std::forward<ArgsType>(args)...) {}
        ~TcpClientWithSSL() override {
            if (m_ssl_box) {
                m_ssl_box->flush();
            }
        }
        void onRecv(const MBuffer::ptr &buf) override {
            if (m_ssl_box) {
                m_ssl_box->onRecv(buf);
            } else {
                TcpClientType::onRecv(buf);
            }
        }
        ssize_t send(MBuffer::ptr buf) {
            if (m_ssl_box) {
                auto size = buf->readAvailable();
                m_ssl_box->onSend(std::move(buf));
                return size;
            }
            return TcpClientType::send(std::move(buf));
        }
        void startConnect(const std::string &url, uint16_t port, float timeout = 1000 * 5, uint16_t local_port = 0) {
            m_host = url;
            TcpClientType::startConnect(url, port, timeout, local_port);
        }
        inline void public_onRecv(const MBuffer::ptr &buf) {
            TcpClientType::onRecv(buf);
        }
        inline void public_send(const MBuffer::ptr &buf) {
            TcpClientType::send(std::move(const_cast<MBuffer::ptr&>(buf)));
        }
        void onConnect(SocketException &e) {
            if (!e) {
                m_ssl_box = std::make_shared<SSL_Box>(false);
                m_ssl_box->setOnDecData([this](const MBuffer::ptr &buf) {
                    public_onRecv(buf);
                });
                m_ssl_box->setOnEncData([this](const MBuffer::ptr &buf) {
                    public_send(buf);
                });
                // must host
                m_ssl_box->setHost(m_host.data());
            }
            TcpClientType::onConnect(e);
        } 
        void setDoNotUseSSL() {
            m_ssl_box.reset();
        }
    private:
        std::string                 m_host;
        std::shared_ptr<SSL_Box>    m_ssl_box;
    };
}

#endif

