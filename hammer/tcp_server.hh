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

    class SSL_Initor {
    public:
        friend class SSL_Box;
        SSL_Initor();
        ~SSL_Initor();
        /**
         * 从文件或字符串中加载公钥和私钥
         * 该证书文件必须同时包含公钥和私钥(cer格式的证书只包括公钥，请使用后面的方法加载)
         * 客户端默认可以不加载证书(除非服务器要求客户端提供证书)
         * @param pem_or_p12 pem或p12文件路径或者文件内容字符串
         * @param server_mode 是否为服务器模式
         * @param password 私钥加密密码
         * @param is_file 参数pem_or_p12是否为文件路径
         * @param is_default 是否为默认证书
         */
        bool loadCertificate(const std::string &pem_or_p12, bool server_mode = true, const std::string &password = "",
                             bool is_file = true, bool is_default = true);
    
        /**
         * 是否忽略无效的证书 默认忽略，强烈建议不要忽略！
         * @param ignore 标记
         */
        void ignoreInvalidCertificate(bool ignore = true);
    
        /**
         * 信任某证书,一般用于客户端信任自签名的证书或自签名CA签署的证书使用
         * 比如说我的客户端要信任我自己签发的证书，那么我们可以只信任这个证书
         * @param pem_p12_cer pem文件或p12文件或cer文件路径或内容
         * @param server_mode 是否为服务器模式
         * @param password pem或p12证书的密码
         * @param is_file 是否为文件路径
         * @return 是否加载成功
         */
        bool trustCertificate(const std::string &pem_p12_cer, bool server_mode = false, const std::string &password = "",
                              bool is_file = true);
    
        /**
         * 信任某证书
         * @param cer 证书公钥
         * @param server_mode 是否为服务模式
         * @return 是否加载成功
         */
        bool trustCertificate(X509 *cer, bool server_mode = false);
    
    private: 
        /**
         * 创建SSL对象
         */
        std::shared_ptr<SSL> makeSSL(bool server_mode);
    
        /**
         * 设置ssl context
         * @param vhost 虚拟主机名
         * @param ctx ssl context
         * @param server_mode ssl context
         * @param is_default 是否为默认证书
         */
        bool setContext(const std::string &vhost, const std::shared_ptr<SSL_CTX> &ctx, bool server_mode, bool is_default = true);
    
        /**
         * 设置SSL_CTX的默认配置
         * @param ctx 对象指针
         */
        void setupCtx(SSL_CTX *ctx);
    
        /**
         * 根据虚拟主机获取SSL_CTX对象
         * @param vhost 虚拟主机名
         * @param server_mode 是否为服务器模式
         * @return SSL_CTX对象
         */
        std::shared_ptr<SSL_CTX> getSSLCtx(const std::string &vhost, bool server_mode);
    
        std::shared_ptr<SSL_CTX> getSSLCtx_l(const std::string &vhost, bool server_mode);
    
        std::shared_ptr<SSL_CTX> getSSLCtxWildcards(const std::string &vhost, bool server_mode);
    
        /**
         * 获取默认的虚拟主机
         */
        std::string defaultVhost(bool server_mode);
    
        /**
         * 完成vhost name 匹配的回调函数
         */
        static int findCertificate(SSL *ssl, int *ad, void *arg);
    
    private:
        struct less_nocase {
            bool operator()(const std::string &x, const std::string &y) const {
                return strcasecmp(x.data(), y.data()) < 0;
            }
        };
    
    private:
        std::string _default_vhost[2];
        std::shared_ptr<SSL_CTX> _ctx_empty[2];
        std::map<std::string, std::shared_ptr<SSL_CTX>, less_nocase> _ctxs[2];
        std::map<std::string, std::shared_ptr<SSL_CTX>, less_nocase> _ctxs_wildcards[2];
    };

    class SSL_Box {
    public:
        SSL_Box(bool server_mode = true, bool enable = true, int buff_size = 32 * 1024);
        ~SSL_Box() {};
    
        void onRecv(const MBuffer::ptr &buffer);
        void onSend(MBuffer::ptr buffer);
        void setOnDecData(const std::function<void(const MBuffer::ptr &)> &cb);
        void setOnEncData(const std::function<void(const MBuffer::ptr &)> &cb);
    
        void shutdown();
        void flush();
        bool setHost(const char *host);
    
    private:
        void flushWriteBio();
        void flushReadBio();
    
    private:
        bool _server_mode;
        bool _send_handshake;
        bool _is_flush = false;
        int _buff_size;
        BIO *_read_bio;
        BIO *_write_bio;
        std::shared_ptr<SSL> _ssl;
        MBuffer::ptr _buffer_send;
        std::function<void(const MBuffer::ptr &)> _on_dec;
        std::function<void(const MBuffer::ptr &)> _on_enc;
    };


}


#endif //HAMMER_TCP_SERVER_HH
