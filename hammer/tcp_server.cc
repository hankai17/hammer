//
// Created by root on 12/16/22.
//

#include "tcp_server.hh"
#include "util.hh"
#include "log.hh"
#include "socket_ops.hh"

#if defined(ENABLE_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#endif //defined(ENABLE_OPENSSL)

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
//openssl版本是否支持sni
#define SSL_ENABLE_SNI
#endif

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

    /// Session
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
        m_socket->shutdownSocket();
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

    /// SessionManager
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

    /// TcpServer
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
        return nullptr;
        //return createSocket(Singleton<EventPollerPool>::instance().getPoller(false));
    }

    void TcpServer::onAcceptConnection(const Socket::ptr &sock) {
        std::weak_ptr<TcpServer> weak_self = std::dynamic_pointer_cast<TcpServer>(shared_from_this());
        auto session = m_session_alloc_cb(std::dynamic_pointer_cast<TcpServer>(shared_from_this()), sock);
        auto success = m_sessions.emplace(session.get(), session).second;

        HAMMER_ASSERT(success = true);
        HAMMER_ASSERT(m_poller->isCurrentThread());

        std::weak_ptr<Session> weak_session = session;
        sock->setOnReadCB([weak_session](const MBuffer::ptr &buf, struct sockaddr *, int) -> void{
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
        sock->setOnWrittenCB([weak_session]() {
            auto strong_session = weak_session.lock();
            if (!strong_session) {
                return false;
            }
            try {
                strong_session->onWritten();
            } catch (SocketException &e) {
                strong_session->shutdown(e);
                return false;
            } catch (std::exception &e) {
                strong_session->shutdown(SocketException(ERRCode::SHUTDOWN, e.what()));
                return false;
            }
            return true;
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
            /*
            auto strong_session = weak_session.lock();
            if (strong_session) {
                strong_session->onError(e);
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

    /// TcpClient
    TcpClient::TcpClient(const EventPoller::ptr &poller) {
        m_poller = (poller == nullptr) ? 
                Singleton<EventPollerPool>::instance().getPoller() : poller;
    }

    TcpClient::~TcpClient() {}

    void TcpClient::startConnect(const std::string &url, uint16_t port, float timeout, uint16_t local_port) {
        std::weak_ptr<TcpClient> weak_self = shared_from_this();
        m_timer = std::make_shared<Timer>(1000 * 2.0f, [weak_self]() {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return false;
            }
            strong_self->onManager();
            return true;
        }, m_poller);
        m_socket = Socket::createSocket(m_poller, false);
        auto sock_ptr = m_socket.get();
        m_socket->setOnErrCB([weak_self, sock_ptr](const SocketException &e) {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return;
            }
            if (sock_ptr != strong_self->m_socket.get()) {
                return;
            }
            strong_self->m_timer.reset();
            strong_self->onError(e);
        });
        sock_ptr->connect(url, port, [weak_self](const SocketException &e) {
            auto strong_self = weak_self.lock();
            if (strong_self) {
                strong_self->onSocketConnect(e);
            }
        }, timeout, "::", local_port);
    }

    ssize_t TcpClient::send(MBuffer::ptr buf) {
        return m_socket->send(std::move(buf));
    }

    void TcpClient::shutdown(const SocketException &e) {
        m_timer.reset();
        m_socket->emitErr(e);
    }

    bool TcpClient::alive() const {
        if (m_timer) {
            return true;
        }
        // TODO
        return true;
    }

    void TcpClient::onSocketConnect(const SocketException &e) {
        if (e) {
            m_timer.reset();
            onConnect(e);
            return;
        }
        std::weak_ptr<TcpClient> weak_self = shared_from_this();
        auto sock_ptr = m_socket.get();
        sock_ptr->setOnReadCB([weak_self, sock_ptr](const MBuffer::ptr &buf, struct sockaddr *addr, int addr_len) {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return;
            }
            if (sock_ptr != strong_self->m_socket.get()) {
                return;
            }
            try {
                strong_self->onRecv(buf);
            } catch (std::exception &e) {
                HAMMER_LOG_WARN(g_logger) << "Exception occurred : " << e.what();
                sock_ptr->emitErr(SocketException(ERRCode::OTHER, e.what()));
            }
        });
        sock_ptr->setOnWrittenCB([weak_self, sock_ptr]() {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return false;
            }
            if (sock_ptr != strong_self->m_socket.get()) {
                return false;
            }
            strong_self->onWritten();     
            return true;
        });
        onConnect(e);
    }

    /// SSL_Initor
    static bool s_ignore_invalid_cer = true;

    void SSL_Initor::ignoreInvalidCertificate(bool ignore) {
        s_ignore_invalid_cer = ignore;
    }
    
    SSL_Initor::SSL_Initor() {
    #if defined(ENABLE_OPENSSL)
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_ciphers();
        OpenSSL_add_all_algorithms();
        CRYPTO_set_locking_callback([](int mode, int n, const char *file, int line) {
            static mutex *s_mutexes = new mutex[CRYPTO_num_locks()];
            static OnceToken token(nullptr, []() {
                delete[] s_mutexes;
            });
            if (mode & CRYPTO_LOCK) {
                s_mutexes[n].lock();
            } else {
                s_mutexes[n].unlock();
            }
        });
    
        CRYPTO_set_id_callback([]() -> unsigned long {
            return (unsigned long) pthread_self();
        });
    
        setContext("", SSLUtil::makeSSLContext(std::vector<std::shared_ptr<X509> >(), nullptr, false), false);
        setContext("", SSLUtil::makeSSLContext(std::vector<std::shared_ptr<X509> >(), nullptr, true), true);
    #endif //defined(ENABLE_OPENSSL)
    }
    
    SSL_Initor::~SSL_Initor() {
    #if defined(ENABLE_OPENSSL)
        EVP_cleanup();
        ERR_free_strings();
        ERR_clear_error();
    #if OPENSSL_VERSION_NUMBER >= 0x10000000L && OPENSSL_VERSION_NUMBER < 0x10100000L
        ERR_remove_thread_state(nullptr);
    #elif OPENSSL_VERSION_NUMBER < 0x10000000L
        ERR_remove_state(0);
    #endif
        CRYPTO_set_locking_callback(nullptr);
        //sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
        CRYPTO_cleanup_all_ex_data();
        CONF_modules_unload(1);
        CONF_modules_free();
    #endif //defined(ENABLE_OPENSSL)
    }
    
    bool SSL_Initor::loadCertificate(const std::string &pem_or_p12, bool server_mode, const std::string &password, bool is_file,
                                     bool is_default) {
        auto cers = SSLUtil::loadPublicKey(pem_or_p12, password, is_file);
        auto key = SSLUtil::loadPrivateKey(pem_or_p12, password, is_file);
        auto ssl_ctx = SSLUtil::makeSSLContext(cers, key, server_mode, true);
        if (!ssl_ctx) {
            return false;
        }
        for (auto &cer : cers) {
            auto server_name = SSLUtil::getServerName(cer.get());
            setContext(server_name, ssl_ctx, server_mode, is_default);
            break;
        }
        return true;
    }
    
    int SSL_Initor::findCertificate(SSL *ssl, int *, void *arg) {
    #if !defined(ENABLE_OPENSSL) || !defined(SSL_ENABLE_SNI)
        return 0;
    #else
        if (!ssl) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    
        SSL_CTX *ctx = nullptr;

        static auto &ref = Singleton<SSL_Initor>::instance();
        const char *vhost = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    
        if (vhost && vhost[0] != '\0') {
            //根据域名找到证书
            ctx = ref.getSSLCtx(vhost, (bool) (arg)).get();
            if (!ctx) {
                //未找到对应的证书
                HAMMER_LOG_WARN(g_logger) << "Can not find any certificate of host: " << vhost
                      << ", select default certificate of: " << ref._default_vhost[(bool) (arg)];
            }
        }
    
        if (!ctx) {
            //客户端未指定域名或者指定的证书不存在，那么选择一个默认的证书
            ctx = ref.getSSLCtx("", (bool) (arg)).get();
        }
    
        if (!ctx) {
            //未有任何有效的证书
            HAMMER_LOG_WARN(g_logger) << "Can not find any available certificate of host: " << (vhost ? vhost : "default host")
                  << ", tls handshake failed";
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    
        SSL_set_SSL_CTX(ssl, ctx);
        return SSL_TLSEXT_ERR_OK;
    #endif
    }
    
    bool SSL_Initor::setContext(const std::string &vhost, const std::shared_ptr<SSL_CTX> &ctx, bool server_mode, bool is_default) {
        if (!ctx) {
            return false;
        }
        setupCtx(ctx.get());
    #if defined(ENABLE_OPENSSL)
        if (vhost.empty()) {
            _ctx_empty[server_mode] = ctx;
    #ifdef SSL_ENABLE_SNI
            if (server_mode) {
                SSL_CTX_set_tlsext_servername_callback(ctx.get(), findCertificate);
                SSL_CTX_set_tlsext_servername_arg(ctx.get(), (void *) server_mode);
            }
    #endif // SSL_ENABLE_SNI
    
        } else {
            _ctxs[server_mode][vhost] = ctx;
            if (is_default) {
                _default_vhost[server_mode] = vhost;
            }
            if (vhost.find("*.") == 0) {
                //通配符证书
                _ctxs_wildcards[server_mode][vhost.substr(1)] = ctx;
            }
            HAMMER_LOG_DEBUG(g_logger) << "Add certificate of: " << vhost;
        }
        return true;
    #else
        HAMMER_LOG_WARN(g_logger) << "ENABLE_OPENSSL disabled, you can not use any features based on openssl";
        return false;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Initor::setupCtx(SSL_CTX *ctx) {
    #if defined(ENABLE_OPENSSL)
        //加载默认信任证书
        SSLUtil::loadDefaultCAs(ctx);
        SSL_CTX_set_cipher_list(ctx, "ALL:!ADH:!LOW:!EXP:!MD5:!3DES:@STRENGTH");
        SSL_CTX_set_verify_depth(ctx, 9);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, [](int ok, X509_STORE_CTX *pStore) {
            if (!ok) {
                int depth = X509_STORE_CTX_get_error_depth(pStore);
                int err = X509_STORE_CTX_get_error(pStore);
                HAMMER_LOG_WARN(g_logger) << "SSL_CTX_set_verify callback, depth: " << depth << " ,err: " << X509_verify_cert_error_string(err);
            }
            return s_ignore_invalid_cer ? 1 : ok;
        });
    
    #ifndef SSL_OP_NO_COMPRESSION
    #define SSL_OP_NO_COMPRESSION 0
    #endif
    #ifndef SSL_MODE_RELEASE_BUFFERS    /* OpenSSL >= 1.0.0 */
    #define SSL_MODE_RELEASE_BUFFERS 0
    #endif
        unsigned long ssloptions = SSL_OP_ALL
                                   | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
                                   | SSL_OP_NO_COMPRESSION;
    
    #ifdef SSL_OP_NO_RENEGOTIATION /* openssl 1.1.0 */
        ssloptions |= SSL_OP_NO_RENEGOTIATION;
    #endif
        SSL_CTX_set_options(ctx, ssloptions);
    
    #endif //defined(ENABLE_OPENSSL)
    }
    
    std::shared_ptr<SSL> SSL_Initor::makeSSL(bool server_mode) {
    #if defined(ENABLE_OPENSSL)
    #ifdef SSL_ENABLE_SNI
        //openssl 版本支持SNI
        return SSLUtil::makeSSL(_ctx_empty[server_mode].get());
    #else
        //openssl 版本不支持SNI，选择默认证书
        return SSLUtil::makeSSL(getSSLCtx("",server_mode).get());
    #endif//SSL_CTRL_SET_TLSEXT_HOSTNAME
    #else
        return nullptr;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    bool SSL_Initor::trustCertificate(X509 *cer, bool server_mode) {
        return SSLUtil::trustCertificate(_ctx_empty[server_mode].get(), cer);
    }
    
    bool SSL_Initor::trustCertificate(const std::string &pem_p12_cer, bool server_mode, const std::string &password, bool is_file) {
        auto cers = SSLUtil::loadPublicKey(pem_p12_cer, password, is_file);
        for (auto &cer : cers) {
            trustCertificate(cer.get(), server_mode);
        }
        return true;
    }
    
    std::shared_ptr<SSL_CTX> SSL_Initor::getSSLCtx(const std::string &vhost, bool server_mode) {
        auto ret = getSSLCtx_l(vhost, server_mode);
        if (ret) {
            return ret;
        }
        return getSSLCtxWildcards(vhost, server_mode);
    }
    
    std::shared_ptr<SSL_CTX> SSL_Initor::getSSLCtxWildcards(const std::string &vhost, bool server_mode) {
        for (auto &pr : _ctxs_wildcards[server_mode]) {
            auto pos = strcasestr(vhost.data(), pr.first.data());
            if (pos && pos + pr.first.size() == &vhost.back() + 1) {
                return pr.second;
            }
        }
        return nullptr;
    }
    
    std::shared_ptr<SSL_CTX> SSL_Initor::getSSLCtx_l(const std::string &vhost_in, bool server_mode) {
        auto vhost = vhost_in;
        if (vhost.empty()) {
            if (!_default_vhost[server_mode].empty()) {
                vhost = _default_vhost[server_mode];
            } else {
                //没默认主机，选择空主机
                if (server_mode) {
                    HAMMER_LOG_WARN(g_logger) << "Server with ssl must have certification and key";
                }
                return _ctx_empty[server_mode];
            }
        }
        //根据主机名查找证书
        auto it = _ctxs[server_mode].find(vhost);
        if (it == _ctxs[server_mode].end()) {
            return nullptr;
        }
        return it->second;
    }
    
    std::string SSL_Initor::defaultVhost(bool server_mode) {
        return _default_vhost[server_mode];
    }

    /// SSL_Box
    SSL_Box::SSL_Box(bool server_mode, bool enable, int buff_size) {
    #if defined(ENABLE_OPENSSL)
        _read_bio = BIO_new(BIO_s_mem());
        _server_mode = server_mode;
        if (enable) {
            _ssl = Singleton<SSL_Initor>::instance().makeSSL(server_mode);
        }
        if (_ssl) {
            _write_bio = BIO_new(BIO_s_mem());
            SSL_set_bio(_ssl.get(), _read_bio, _write_bio);
            _server_mode ? SSL_set_accept_state(_ssl.get()) : SSL_set_connect_state(_ssl.get());
        } else {
            HAMMER_LOG_WARN(g_logger) << "makeSSL failed";
        }
        _send_handshake = false;
        _buff_size = buff_size;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Box::shutdown() {
    #if defined(ENABLE_OPENSSL)
        _buffer_send->clear();
        int ret = SSL_shutdown(_ssl.get());
        if (ret != 1) {
            HAMMER_LOG_WARN(g_logger) << "SSL_shutdown failed: " << SSLUtil::getLastError();
        } else {
            flush();
        }
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Box::onRecv(const MBuffer::ptr &buffer) {
        if (!buffer->readAvailable()) {
            return;
        }
        if (!_ssl) {
            if (_on_dec) {
                _on_dec(buffer);
            }
            return;
        }
    #if defined(ENABLE_OPENSSL)
        uint32_t offset = 0;
        uint32_t size = buffer->readAvailable();
        while (offset < size) {
            auto nwrite = BIO_write(_read_bio, buffer->data() + offset, size - offset); // 写入bio 让bio解密?
            if (nwrite > 0) {
                //部分或全部写入bio完毕
                offset += nwrite;
                flush();
                continue;
            }
            //nwrite <= 0,出现异常
            HAMMER_LOG_WARN(g_logger) << "Ssl error on BIO_write: " << SSLUtil::getLastError();
            shutdown();
            break;
        }
        buffer->consume(offset);
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Box::onSend(MBuffer::ptr buffer) { // 传入密文
        if (!buffer->readAvailable()) {
            return;
        }
        if (!_ssl) {
            if (_on_enc) {
                _on_enc(buffer);
            }
            return;
        }
    #if defined(ENABLE_OPENSSL)
        if (!_server_mode && !_send_handshake) {
            _send_handshake = true;
            SSL_do_handshake(_ssl.get());
        }
        _buffer_send->copyIn(*buffer.get());
        flush();
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Box::setOnDecData(const std::function<void(const MBuffer::ptr &)> &cb) {
        _on_dec = cb;
    }
    
    void SSL_Box::setOnEncData(const std::function<void(const MBuffer::ptr &)> &cb) {
        _on_enc = cb;
    }
    
    void SSL_Box::flushWriteBio() {
    #if defined(ENABLE_OPENSSL)
        int total = 0;
        int nread = 0;
        auto buffer = std::make_shared<MBuffer>();
        buffer->reserve(_buff_size);
        auto buf_size = buffer->writeAvailable() - 1;
        do {
            nread = BIO_read(_write_bio, buffer->data() + total, buf_size - total);
            if (nread > 0) {
                total += nread;
            }
        } while (nread > 0 && buf_size - total > 0);
    
        if (!total) {
            //未有数据
            return;
        }
    
        //触发此次回调
        buffer->data()[total] = '\0';
        if (_on_enc) {
            _on_enc(buffer);
        }
    
        if (nread > 0) {
            //还有剩余数据，读取剩余数据
            flushWriteBio();
        }
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Box::flushReadBio() {
    #if defined(ENABLE_OPENSSL)
        int total = 0;
        int nread = 0;
        auto buffer = std::make_shared<MBuffer>();
        buffer->reserve(_buff_size);
        auto buf_size = buffer->writeAvailable() - 1;
        do {
            nread = SSL_read(_ssl.get(), buffer->data() + total, buf_size - total); // 拿到解密的数据 即拿到明文
            if (nread > 0) {
                total += nread;
            }
        } while (nread > 0 && buf_size - total > 0);
    
        if (!total) {
            return;
        }
    
        buffer->data()[total] = '\0';
        if (_on_dec) {
            _on_dec(buffer);
        }
    
        if (nread > 0) {
            flushReadBio();
        }
    #endif //defined(ENABLE_OPENSSL)
    }
    
    void SSL_Box::flush() {
    #if defined(ENABLE_OPENSSL)
        if (_is_flush) {
            return;
        }
        OnceToken token([&] {
            _is_flush = true;
        }, [&]() {
            _is_flush = false;
        });
    
        flushReadBio();
        if (!SSL_is_init_finished(_ssl.get()) || _buffer_send->readAvailable() == 0) {
            //ssl未握手结束或没有需要发送的数据
            flushWriteBio();
            return;
        }
    
        //加密数据并发送
        do {
            uint32_t offset = 0;
            uint32_t size = _buffer_send->readAvailable();
            while (offset < size) {
                auto nwrite = SSL_write(_ssl.get(), _buffer_send->data() + offset, size - offset);
                if (nwrite > 0) {
                    offset += nwrite;
                    flushWriteBio();
                    continue;
                }
                //nwrite <= 0,出现异常
                break;
            }
    
            if (offset != size) {
                //这个包未消费完毕，出现了异常,清空数据并断开ssl
                HAMMER_LOG_WARN(g_logger) << "Ssl error on SSL_write: " << SSLUtil::getLastError();
                shutdown();
                break;
            }
            _buffer_send->consume(size); 
        } while (0);
    #endif //defined(ENABLE_OPENSSL)
    }
    
    bool SSL_Box::setHost(const char *host) {
        if (!_ssl) {
            return false;
        }
    #ifdef SSL_ENABLE_SNI
        return 0 != SSL_set_tlsext_host_name(_ssl.get(), host);
    #else
        return false;
    #endif//SSL_ENABLE_SNI
    }

}
