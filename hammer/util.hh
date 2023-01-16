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
#include <byteswap.h>

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

    /**
     * ssl证书后缀一般分为以下几种
     * pem:这个是base64的字符编码串，可能存在公钥、私钥或者两者都存在
     * cer:只且只能是公钥，可以与pem的私钥配合使用
     * p12:必须包括私钥和公钥
     */
    class SSLUtil {
    public:
        static std::string getLastError();
        /**
         * 加载公钥证书，支持pem,p12,cer后缀
         * 由于openssl加载p12证书时会校验公钥和私钥是否匹对，所以加载p12的公钥时可能需要传入证书密码
         * @param file_path_or_data 文件路径或文件内容
         * @param isFile 是否为文件
         * @return 公钥证书列表
         */
        static std::vector<std::shared_ptr<X509> > loadPublicKey(const std::string &file_path_or_data, const std::string &passwd = "", bool isFile = true);
        /**
         * 加载私钥证书，支持pem,p12后缀
         * @param file_path_or_data 文件路径或文件内容
         * @param passwd 密码
         * @param isFile 是否为文件
         * @return 私钥证书
         */
        static std::shared_ptr<EVP_PKEY> loadPrivateKey(const std::string &file_path_or_data, const std::string &passwd = "", bool isFile = true);

        /**
         * 创建SSL_CTX对象
         * @param cer 公钥数组
         * @param key 私钥
         * @param serverMode 是否为服务器模式或客户端模式
         * @return SSL_CTX对象
         */
        static std::shared_ptr<SSL_CTX> makeSSLContext(const std::vector<std::shared_ptr<X509> > &cers, const std::shared_ptr<EVP_PKEY> &key, bool serverMode = true, bool checkKey = false);

        /**
         * 创建ssl对象
         * @param ctx SSL_CTX对象
         */
        static std::shared_ptr<SSL> makeSSL(SSL_CTX *ctx);

        /**
         * specifies that the default locations from which CA certificates are loaded should be used.
         * There is one default directory and one default file.
         * The default CA certificates directory is called "certs" in the default OpenSSL directory.
         * Alternatively the SSL_CERT_DIR environment variable can be defined to override this location.
         * The default CA certificates file is called "cert.pem" in the default OpenSSL directory.
         *  Alternatively the SSL_CERT_FILE environment variable can be defined to override this location.
         * 信任/usr/local/ssl/certs/目录下的所有证书/usr/local/ssl/cert.pem的证书
         * 环境变量SSL_CERT_FILE将替换/usr/local/ssl/cert.pem的路径
         */
        static bool loadDefaultCAs(SSL_CTX *ctx);

        /**
         * 信任某公钥
         */
        static bool trustCertificate(SSL_CTX *ctx, X509 *cer);

        /**
         * 验证证书合法性
         * @param cer 待验证的证书
         * @param ... 信任的CA根证书，X509类型，以nullptr结尾
         * @return 是否合法
         */
        static bool verifyX509(X509 *cer, ...);

        /**
         * 使用公钥加解密数据
         * @param cer 公钥，必须为ras的公钥
         * @param in_str 加密或解密的原始数据，实测加密最大支持245个字节，加密后数据长度固定为256个字节
         * @param enc_or_dec true:加密,false:解密
         * @return 加密或解密后的数据
         */
        static std::string cryptWithRsaPublicKey(X509 *cer, const std::string &in_str, bool enc_or_dec);

        /**
         * 使用私钥加解密数据
         * @param private_key 私钥，必须为ras的私钥
         * @param in_str 加密或解密的原始数据，实测加密最大支持245个字节，加密后数据长度固定为256个字节
         * @param enc_or_dec true:加密,false:解密
         * @return 加密或解密后的数据
         */
        static std::string cryptWithRsaPrivateKey(EVP_PKEY *private_key, const std::string &in_str, bool enc_or_dec);

        /**
         * 获取证书域名
         * @param cer 证书公钥
         * @return 证书域名
         */
        static std::string getServerName(X509 *cer);
    
    };
}

#endif //HAMMER_UTIL_HH
