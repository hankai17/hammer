//
// Created by root on 12/6/22.
//

#ifndef HAMMER_UTIL_HH
#define HAMMER_UTIL_HH

#include <unistd.h>
#include <syscall.h>
#include <assert.h>
#include <semaphore.h>
#include <functional>
#include <vector>
#include <thread>
#include <list>
#include <map>
#include <byteswap.h>
#include <strings.h>
#include "mbuffer.hh"

#define HAMMER_ASSERT(x) \
    if (!(x)) { \
        HAMMER_LOG_ERROR(HAMMER_LOG_ROOT()) << "ASSERTION: " #x \
        << "\nbacktrace:\n" \
        << hammer::BacktraceToString(100, 2, "    "); \
        assert(x); \
    }
#define HAMMER_LITTLE_ENDIAN 1
#define HAMMER_BIG_ENDIAN 2

typedef struct x509_st X509;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
typedef struct bio_st BIO;

namespace hammer {

    int GetThreadId();
    void setThreadName(const std::string &name);
    void Backtrace(std::vector<std::string> &bt, int size, int skip = 1);
    std::string BacktraceToString(int size = 64, int skip = 2, const std::string& prefix = " ");

    class semaphore {
    public:
        explicit semaphore(size_t count = 0) {
            sem_init(&m_sem, 0, count);
        }
        ~semaphore() {
            sem_destroy(&m_sem);
        }
        void notify(size_t n = 1) {
            while (n--) {
                sem_post(&m_sem);
            }
        }
        void wait() {
            sem_wait(&m_sem);
        }
    private:
        semaphore(const semaphore&) = delete;
        semaphore &operator=(const semaphore&) = delete;
        semaphore(semaphore&&) = delete;
        sem_t   m_sem;
    };

    template<typename T>
    class List : public std::list<T> {
    public:
        template<typename ...ARGS>
        List(ARGS &&...args) : std::list<T>(std::forward<ARGS>(args)...) {};
        ~List() = default;
        void append(List<T> &other) {
            if (other.empty()) {
                return;
            }
            insert(this->end(), other.begin(), other.end());
            other.clear();
        }
        template<typename FUNC>
        void foreach(FUNC &&func) {
            for (auto &t : *this) {
                func(t);
            }
        }
        template<typename FUNC>
        void foreach(FUNC &&func) const {
            for (auto &t : *this) {
                func(t);
            }
        }
    };

    class OnceToken {
    public:
        using task = std::function<void(void)>;
        template<typename FUNC>
        OnceToken(const FUNC &onConstructed, task onDestroied = nullptr) {
            onConstructed();
            m_on_destroied = std::move(onDestroied);
        }
        OnceToken(std::nullptr_t, task onDestroied = nullptr) {
            m_on_destroied = std::move(onDestroied);
        }
        ~OnceToken() {
            if (m_on_destroied) {
                m_on_destroied();
            }
        }
    private:
        OnceToken() = delete;
        OnceToken(const OnceToken &) = delete;
        OnceToken &operator=(const OnceToken &) = delete;
        OnceToken(OnceToken &&) = delete;
        OnceToken &operator=(OnceToken &&) = delete;
        task m_on_destroied = nullptr;
    };

    template<typename T>
    void nop(T*) {}

    template <typename T>
    typename std::enable_if<sizeof(T) == sizeof(uint64_t), T>::type
    byteswap(T value) {
        return (T)bswap_64((uint64_t)value);
    }

    template <typename T>
    typename std::enable_if<sizeof(T) == sizeof(uint32_t), T>::type
    byteswap(T value) {
        return (T)bswap_32((uint32_t)value);
    }

    template <typename T>
    typename std::enable_if<sizeof(T) == sizeof(uint16_t), T>::type
    byteswap(T value) {
        return (T)bswap_16((uint16_t)value);
    }

#if BYTE_ORDER == BIG_ENDIAN
#define HAMMER_BYTE_ORDER HAMMER_BIG_ENDIAN
#else
#define HAMMER_BYTE_ORDER HAMMER_LITTLE_ENDIAN
#endif

#if HAMMER_BYTE_ORDER == HAMMER_BIG_ENDIAN
    //TODO
#else
    template <typename T>
    T byteswapOnLittleEndian(T t) {
        return byteswap(t);
    }

    template <typename T>
    T byteswapOnBigEndian(T t) {
        return t;
    }
#endif

	void no_locks_localtime(struct tm *tmp, time_t t);
	void local_time_init();
	int get_daylight_active();
	uint64_t getCurrentMillSecond(bool system_time = false);
	uint64_t getCurrentMicroSecond(bool system_time = false);
    bool setThreadAffinity(int i);

    class SSLUtil {
    public:
        static std::string getLastError();
        static std::vector<std::shared_ptr<X509> > loadPublicKey(const std::string &file_path_or_data, const std::string &passwd = "", bool isFile = true);
        static std::shared_ptr<EVP_PKEY> loadPrivateKey(const std::string &file_path_or_data, const std::string &passwd = "", bool isFile = true);
        static std::shared_ptr<SSL_CTX> makeSSLContext(const std::vector<std::shared_ptr<X509> > &cers, const std::shared_ptr<EVP_PKEY> &key, bool serverMode = true, bool checkKey = false);
        static std::shared_ptr<SSL> makeSSL(SSL_CTX *ctx);
        static bool loadDefaultCAs(SSL_CTX *ctx);
        static bool trustCertificate(SSL_CTX *ctx, X509 *cer);
        static bool verifyX509(X509 *cer, ...);
        static std::string cryptWithRsaPublicKey(X509 *cer, const std::string &in_str, bool enc_or_dec);
        static std::string cryptWithRsaPrivateKey(EVP_PKEY *private_key, const std::string &in_str, bool enc_or_dec);
        static std::string getServerName(X509 *cer);
    };

    class SSL_Initor {
    public:
        friend class SSL_Box;
        SSL_Initor();
        ~SSL_Initor();
        bool loadCertificate(const std::string &pem_or_p12, bool server_mode = true, const std::string &password = "",
                             bool is_file = true, bool is_default = true);
        void ignoreInvalidCertificate(bool ignore = true);
        bool trustCertificate(const std::string &pem_p12_cer, bool server_mode = false, const std::string &password = "",
                              bool is_file = true);
        bool trustCertificate(X509 *cer, bool server_mode = false);
    private:
        std::shared_ptr<SSL> makeSSL(bool server_mode);
        bool setContext(const std::string &vhost, const std::shared_ptr<SSL_CTX> &ctx, bool server_mode, bool is_default = true);
        void setupCtx(SSL_CTX *ctx);
        std::shared_ptr<SSL_CTX> getSSLCtx(const std::string &vhost, bool server_mode);
        std::shared_ptr<SSL_CTX> getSSLCtx_l(const std::string &vhost, bool server_mode);
        std::shared_ptr<SSL_CTX> getSSLCtxWildcards(const std::string &vhost, bool server_mode);
        std::string defaultVhost(bool server_mode);
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

#endif //HAMMER_UTIL_HH
