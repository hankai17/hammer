//
// Created by root on 12/6/22.
//

#include "util.hh"
#include "log.hh"
#include <execinfo.h>
#include <iostream>
#include <sstream>
#include <atomic>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#if defined(ENABLE_OPENSSL)
#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#endif //defined(ENABLE_OPENSSL)

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");
    pid_t GetThreadId() {
        return syscall(SYS_gettid);
        //return std::this_thread::get_id();
    }

    void setThreadName(const std::string &name) {
    }

    void Backtrace(std::vector<std::string> &bt, int size, int skip) {
        void** array = (void**)malloc(sizeof(void*) * size);
        size_t s = ::backtrace(array, size);
        char** strings = backtrace_symbols(array, size);
        if (strings == NULL) {
            free(array);
            return;
        }

        for (size_t i = skip; i < s; i++) {
            bt.push_back(strings[i]);
        }

        free(array);
        free(strings);
    }

    std::string BacktraceToString(int size, int skip, const std::string& prefix) {
        std::vector<std::string> bt;
        Backtrace(bt, size, skip);
        std::stringstream ss;
        for (size_t i = 0; i < bt.size(); i++) {
            ss << prefix << bt[i] << std::endl;
        }
        return ss.str();
    }

	static int _daylight_active;
	static long _current_timezone;
	int get_daylight_active() {
    	return _daylight_active;
	}

	static int is_leap_year(time_t year) {
    	if (year % 4)
    	    return 0; /* A year not divisible by 4 is not leap. */
    	else if (year % 100)
    	    return 1; /* If div by 4 and not 100 is surely leap. */
    	else if (year % 400)
    	    return 0; /* If div by 100 *and* not by 400 is not leap. */
    	else
    	    return 1; /* If div by 100 and 400 is leap. */
	}

	void no_locks_localtime(struct tm *tmp, time_t t) {
	    const time_t secs_min = 60;
	    const time_t secs_hour = 3600;
	    const time_t secs_day = 3600 * 24;
	
	    t -= _current_timezone; /* Adjust for timezone. */
	    t += 3600 * get_daylight_active(); /* Adjust for daylight time. */
	    time_t days = t / secs_day; /* Days passed since epoch. */
	    time_t seconds = t % secs_day; /* Remaining seconds. */
	
	    tmp->tm_isdst = get_daylight_active();
	    tmp->tm_hour = seconds / secs_hour;
	    tmp->tm_min = (seconds % secs_hour) / secs_min;
	    tmp->tm_sec = (seconds % secs_hour) % secs_min;
	#ifndef _WIN32
	    tmp->tm_gmtoff = -_current_timezone;
	#endif
	    /* 1/1/1970 was a Thursday, that is, day 4 from the POV of the tm structure
	     * where sunday = 0, so to calculate the day of the week we have to add 4
	     * and take the modulo by 7. */
	    tmp->tm_wday = (days + 4) % 7;
	
	    /* Calculate the current year. */
	    tmp->tm_year = 1970;
	    while (1) {
	        /* Leap years have one day more. */
	        time_t days_this_year = 365 + is_leap_year(tmp->tm_year);
	        if (days_this_year > days)
	            break;
	        days -= days_this_year;
	        tmp->tm_year++;
	    }
	    tmp->tm_yday = days; /* Number of day of the current year. */
	
	    /* We need to calculate in which month and day of the month we are. To do
	     * so we need to skip days according to how many days there are in each
	     * month, and adjust for the leap year that has one more day in February. */
	    int mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
	    mdays[1] += is_leap_year(tmp->tm_year);
	
	    tmp->tm_mon = 0;
	    while (days >= mdays[tmp->tm_mon]) {
	        days -= mdays[tmp->tm_mon];
	        tmp->tm_mon++;
	    }
	
	    tmp->tm_mday = days + 1; /* Add 1 since our 'days' is zero-based. */
	    tmp->tm_year -= 1900; /* Surprisingly tm_year is year-1900. */
	}
	
	void local_time_init() {
	    /* Obtain timezone and daylight info. */
	    tzset(); /* Now 'timezome' global is populated. */
	#if defined(__linux__) || defined(__sun)
	    _current_timezone  = timezone;
	#elif defined(_WIN32)
	    time_t time_utc;
	    struct tm tm_local;
	
	    // Get the UTC time
	    time(&time_utc);
	
	    // Get the local time
	    // Use localtime_r for threads safe for linux
	    //localtime_r(&time_utc, &tm_local);
	    localtime_s(&tm_local, &time_utc);
	
	    time_t time_local;
	    struct tm tm_gmt;
	
	    // Change tm to time_t
	    time_local = mktime(&tm_local);
	
	    // Change it to GMT tm
	    //gmtime_r(&time_utc, &tm_gmt);//linux
	    gmtime_s(&tm_gmt, &time_utc);
	
	    int time_zone = tm_local.tm_hour - tm_gmt.tm_hour;
	    if (time_zone < -12) {
	        time_zone += 24;
	    }
	    else if (time_zone > 12) {
	        time_zone -= 24;
	    }
	
	    _current_timezone = time_zone;
	#else
	    struct timeval tv;
	    struct timezone tz;
	    gettimeofday(&tv, &tz);
	    _current_timezone = tz.tz_minuteswest * 60L;
	#endif
	    time_t t = time(NULL);
	    struct tm *aux = localtime(&t);
	    _daylight_active = aux->tm_isdst;
	} 

	struct tm getLocalTime(time_t sec) {
	    struct tm tm;
	#ifdef _WIN32
	    localtime_s(&tm, &sec);
	#else
	    no_locks_localtime(&tm, sec);
	#endif //_WIN32
	    return tm;
	}
	
	static long s_gmtoff = 0;
	static OnceToken s_token([](){
		local_time_init();
	    s_gmtoff = getLocalTime(time(nullptr)).tm_gmtoff;
	});

	static inline uint64_t getCurrentMicrosecondOrigin() {
		struct timeval tv;
		gettimeofday(&tv, nullptr);
		return tv.tv_sec * 1000000LL + tv.tv_usec;
	}

	static std::atomic<uint64_t>	s_current_mic_sec(0);
	static std::atomic<uint64_t>	s_current_mil_sec(0);
	static std::atomic<uint64_t>	s_current_mic_sec_system(getCurrentMicrosecondOrigin());
	static std::atomic<uint64_t>	s_current_mil_sec_system(getCurrentMicrosecondOrigin()/1000);

	static inline bool initMilSecondThread() {
		static std::thread s_thread([]() {
			setThreadName("timestamp thread");
			uint64_t last = getCurrentMicrosecondOrigin();
			uint64_t now;
			uint64_t mic_sec = 0;
			while (1) {
				now = getCurrentMicrosecondOrigin();
				s_current_mic_sec_system.store(now, std::memory_order_release);
				s_current_mil_sec_system.store(now/1000, std::memory_order_release);
				int64_t expired = now - last;
				last = now;
				if (expired > 0 && expired < 1000 * 1000) {
					mic_sec += expired;
					s_current_mic_sec.store(mic_sec, std::memory_order_release);
					s_current_mil_sec.store(mic_sec/1000, std::memory_order_release);
				} else if (expired != 0) {
					//
				}
				usleep(500);
			}
		});
		static OnceToken s_token([](){
			s_thread.detach();
		});
		return true;
	}

	uint64_t getCurrentMillSecond(bool system_time) {
		initMilSecondThread();
		if (system_time) {
			return s_current_mil_sec_system.load(std::memory_order_acquire);
		}
		return s_current_mil_sec.load(std::memory_order_acquire);
	}

	uint64_t getCurrentMicroSecond(bool system_time) {
		initMilSecondThread();
		if (system_time) {
			return s_current_mic_sec_system.load(std::memory_order_acquire);
		}
		return s_current_mic_sec.load(std::memory_order_acquire);
	}

    bool setThreadAffinity(int i) {
#if (defined(__linux) || defined(__linux__)) && !defined(ANDROID)
        cpu_set_t mask;
        CPU_ZERO(&mask);
        if (i >= 0) {
            CPU_SET(i, &mask);
        } else {
            for (auto j = 0u; j < std::thread::hardware_concurrency(); ++j) {
                CPU_SET(j, &mask);
            }
        }
        if (!pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask)) {
            return true;
        }
#endif
    return false;
    }

    /// SSL
    std::string SSLUtil::getLastError() {
    #if defined(ENABLE_OPENSSL)
        unsigned long errCode = ERR_get_error();
        if (errCode != 0) {
            char buffer[256];
            ERR_error_string_n(errCode, buffer, sizeof(buffer));
            return buffer;
        } else
    #endif //defined(ENABLE_OPENSSL)
        {
            return "No error";
        }
    }
    
    #if defined(ENABLE_OPENSSL)
    static int getCerType(BIO *bio, const char *passwd, X509 **x509, int type) {
        //尝试pem格式
        if (type == 1 || type == 0) {
            if (type == 0) {
                BIO_reset(bio);
            }
            // 尝试PEM格式
            *x509 = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
            if (*x509) {
                return 1;
            }
        }
    
        if (type == 2 || type == 0) {
            if (type == 0) {
                BIO_reset(bio);
            }
            //尝试DER格式
            *x509 = d2i_X509_bio(bio, nullptr);
            if (*x509) {
                return 2;
            }
        }
    
        if (type == 3 || type == 0) {
            if (type == 0) {
                BIO_reset(bio);
            }
            //尝试p12格式
            PKCS12 *p12 = d2i_PKCS12_bio(bio, nullptr);
            if (p12) {
                EVP_PKEY *pkey = nullptr;
                PKCS12_parse(p12, passwd, &pkey, x509, nullptr);
                PKCS12_free(p12);
                if (pkey) {
                    EVP_PKEY_free(pkey);
                }
                if (*x509) {
                    return 3;
                }
            }
        }
    
        return 0;
    }
    #endif //defined(ENABLE_OPENSSL)
    
    std::vector<std::shared_ptr<X509> > SSLUtil::loadPublicKey(const std::string &file_path_or_data, const std::string &passwd, bool isFile) {
        std::vector<std::shared_ptr<X509> > ret;
    #if defined(ENABLE_OPENSSL)
        BIO *bio = isFile ? BIO_new_file((char *) file_path_or_data.data(), "r") :
                   BIO_new_mem_buf((char *) file_path_or_data.data(), file_path_or_data.size());
        if (!bio) {
            std::cout << (isFile ? "BIO_new_file" : "BIO_new_mem_buf") << " failed: " << getLastError() << std::endl;
            return ret;
        }
    
        OnceToken token0(nullptr, [&]() {
            BIO_free(bio);
        });
    
        int cer_type = 0;
        X509 *x509 = nullptr;
        do {
            cer_type = getCerType(bio, passwd.data(), &x509, cer_type);
            if (cer_type) {
                ret.push_back(std::shared_ptr<X509>(x509, [](X509 *ptr) { X509_free(ptr); }));
            }
        } while (cer_type != 0);
        return ret;
    #else
        return ret;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    std::shared_ptr<EVP_PKEY> SSLUtil::loadPrivateKey(const std::string &file_path_or_data, const std::string &passwd, bool isFile) {
    #if defined(ENABLE_OPENSSL)
        BIO *bio = isFile ?
                   BIO_new_file((char *) file_path_or_data.data(), "r") :
                   BIO_new_mem_buf((char *) file_path_or_data.data(), file_path_or_data.size());
        if (!bio) {
            std::cout << (isFile ? "BIO_new_file" : "BIO_new_mem_buf") << " failed: " << getLastError() << std::endl;
            return nullptr;
        }
    
        pem_password_cb *cb = [](char *buf, int size, int rwflag, void *userdata) -> int {
            const std::string *passwd = (const std::string *) userdata;
            size = size < (int) passwd->size() ? size : (int) passwd->size();
            memcpy(buf, passwd->data(), size);
            return size;
        };
    
        OnceToken token0(nullptr, [&]() {
            BIO_free(bio);
        });
    
        //尝试pem格式
        EVP_PKEY *evp_key = PEM_read_bio_PrivateKey(bio, nullptr, cb, (void *) &passwd);
        if (!evp_key) {
            //尝试p12格式
            BIO_reset(bio);
            PKCS12 *p12 = d2i_PKCS12_bio(bio, nullptr);
            if (!p12) {
                return nullptr;
            }
            X509 *x509 = nullptr;
            PKCS12_parse(p12, passwd.data(), &evp_key, &x509, nullptr);
            PKCS12_free(p12);
            if (x509) {
                X509_free(x509);
            }
            if (!evp_key) {
                return nullptr;
            }
        }
    
        return std::shared_ptr<EVP_PKEY>(evp_key, [](EVP_PKEY *ptr) {
            EVP_PKEY_free(ptr);
        });
    #else
        return nullptr;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    std::shared_ptr<SSL_CTX> SSLUtil::makeSSLContext(const std::vector<std::shared_ptr<X509> > &cers, const std::shared_ptr<EVP_PKEY> &key, bool serverMode, bool checkKey) {
    #if defined(ENABLE_OPENSSL)
        SSL_CTX *ctx = SSL_CTX_new(serverMode ? SSLv23_server_method() : SSLv23_client_method());
        if (!ctx) {
            std::cout << "SSL_CTX_new " << (serverMode ? "SSLv23_server_method" : "SSLv23_client_method") << " failed: " << getLastError() << std::endl;
            return nullptr;
        }
        int i = 0;
        for (auto &cer : cers) {
            //加载公钥
            if (i++ == 0) {
                //SSL_CTX_use_certificate内部会调用X509_up_ref,所以这里不用X509_dup
                SSL_CTX_use_certificate(ctx, cer.get());
            } else {
                //需要先拷贝X509对象，否则指针会失效
                SSL_CTX_add_extra_chain_cert(ctx, X509_dup(cer.get()));
            }
        }
    
        if (key) {
            //提供了私钥
            if (SSL_CTX_use_PrivateKey(ctx, key.get()) != 1) {
                std::cout << "SSL_CTX_use_PrivateKey failed: " << getLastError() << std::endl;
                SSL_CTX_free(ctx);
                return nullptr;
            }
        }
    
        if (key || checkKey) {
            //加载私钥成功
            if (SSL_CTX_check_private_key(ctx) != 1) {
                std::cout << "SSL_CTX_check_private_key failed: " << getLastError() << std::endl;
                SSL_CTX_free(ctx);
                return nullptr;
            }
        }
    
        //公钥私钥匹配或者没有公私钥
        return std::shared_ptr<SSL_CTX>(ctx, [](SSL_CTX *ptr) { SSL_CTX_free(ptr); });
    #else
        return nullptr;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    std::shared_ptr<SSL> SSLUtil::makeSSL(SSL_CTX *ctx) {
    #if defined(ENABLE_OPENSSL)
        auto *ssl = SSL_new(ctx);
        if (!ssl) {
            return nullptr;
        }
        return std::shared_ptr<SSL>(ssl, [](SSL *ptr) {
            SSL_free(ptr);
        });
    #else
        return nullptr;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    bool SSLUtil::loadDefaultCAs(SSL_CTX *ctx) {
    #if defined(ENABLE_OPENSSL)
        if (!ctx) {
            return false;
        }
    
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            std::cout << "SSL_CTX_set_default_verify_paths failed: " << getLastError() << std::endl;
            return false;
        }
        return true;
    #else
        return false;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    bool SSLUtil::trustCertificate(SSL_CTX *ctx, X509 *cer) {
    #if defined(ENABLE_OPENSSL)
        X509_STORE *store = SSL_CTX_get_cert_store(ctx);
        if (store && cer) {
            if (X509_STORE_add_cert(store, cer) != 1) {
                std::cout << "X509_STORE_add_cert failed: " << getLastError() << std::endl;
                return false;
            }
            return true;
        }
    #endif //defined(ENABLE_OPENSSL)
        return false;
    }
    
    bool SSLUtil::verifyX509(X509 *cer, ...) {
    #if defined(ENABLE_OPENSSL)
        va_list args;
        va_start(args, cer);
        X509_STORE *store = X509_STORE_new();
        do {
            X509 *ca;
            if ((ca = va_arg(args, X509*)) == nullptr) {
                break;
            }
            X509_STORE_add_cert(store, ca);
        } while (true);
        va_end(args);
    
        X509_STORE_CTX *store_ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(store_ctx, store, cer, nullptr);
        auto ret = X509_verify_cert(store_ctx);
        if (ret != 1) {
            int depth = X509_STORE_CTX_get_error_depth(store_ctx);
            int err = X509_STORE_CTX_get_error(store_ctx);
            std::cout << "X509_verify_cert failed, depth: " << depth << ", err: " << X509_verify_cert_error_string(err) << std::endl;
        }
    
        X509_STORE_CTX_free(store_ctx);
        X509_STORE_free(store);
        return ret == 1;
    #else
        std::cout << "ENABLE_OPENSSL disabled, you can not use any features based on openssl" << std::endl;
        return false;
    #endif //defined(ENABLE_OPENSSL)
    }
    
    #ifdef ENABLE_OPENSSL
    #ifndef X509_F_X509_PUBKEY_GET0
    EVP_PKEY *X509_get0_pubkey(X509 *x){
        EVP_PKEY *ret = X509_get_pubkey(x);
        if(ret){
            EVP_PKEY_free(ret);
        }
        return ret;
    }
    #endif //X509_F_X509_PUBKEY_GET0
    
    #ifndef EVP_F_EVP_PKEY_GET0_RSA
    RSA *EVP_PKEY_get0_RSA(EVP_PKEY *pkey){
        RSA *ret = EVP_PKEY_get1_RSA(pkey);
        if(ret){
            RSA_free(ret);
        }
        return ret;
    }
    #endif //EVP_F_EVP_PKEY_GET0_RSA
    #endif //ENABLE_OPENSSL
    
    std::string SSLUtil::cryptWithRsaPublicKey(X509 *cer, const std::string &in_str, bool enc_or_dec) {
    #if defined(ENABLE_OPENSSL)
        EVP_PKEY *public_key = X509_get0_pubkey(cer);
        if (!public_key) {
            return "";
        }
        auto rsa = EVP_PKEY_get1_RSA(public_key);
        if (!rsa) {
            return "";
        }
        std::string out_str(RSA_size(rsa), '\0');
        int ret = 0;
        if (enc_or_dec) {
            ret = RSA_public_encrypt(in_str.size(), (uint8_t *) in_str.data(), (uint8_t *) out_str.data(), rsa,
                                     RSA_PKCS1_PADDING);
        } else {
            ret = RSA_public_decrypt(in_str.size(), (uint8_t *) in_str.data(), (uint8_t *) out_str.data(), rsa,
                                     RSA_PKCS1_PADDING);
        }
        if (ret > 0) {
            out_str.resize(ret);
            return out_str;
        }
        std::cout << (enc_or_dec ? "RSA_public_encrypt" : "RSA_public_decrypt") << " failed: " << getLastError() << std::endl;
        return "";
    #else
        std::cout << "ENABLE_OPENSSL disabled, you can not use any features based on openssl" << std::endl;
        return "";
    #endif //defined(ENABLE_OPENSSL)
    }
    
    std::string SSLUtil::cryptWithRsaPrivateKey(EVP_PKEY *private_key, const std::string &in_str, bool enc_or_dec) {
    #if defined(ENABLE_OPENSSL)
        auto rsa = EVP_PKEY_get1_RSA(private_key);
        if (!rsa) {
            return "";
        }
        std::string out_str(RSA_size(rsa), '\0');
        int ret = 0;
        if (enc_or_dec) {
            ret = RSA_private_encrypt(in_str.size(), (uint8_t *) in_str.data(), (uint8_t *) out_str.data(), rsa,
                                      RSA_PKCS1_PADDING);
        } else {
            ret = RSA_private_decrypt(in_str.size(), (uint8_t *) in_str.data(), (uint8_t *) out_str.data(), rsa,
                                      RSA_PKCS1_PADDING);
        }
        if (ret > 0) {
            out_str.resize(ret);
            return out_str;
        }
        std::cout << getLastError() << std::endl;
        return "";
    #else
        std::cout << "ENABLE_OPENSSL disabled, you can not use any features based on openssl" << std::endl;
        return "";
    #endif //defined(ENABLE_OPENSSL)
    }
    
    std::string SSLUtil::getServerName(X509 *cer) {
    #if defined(ENABLE_OPENSSL) && defined(SSL_CTRL_SET_TLSEXT_HOSTNAME)
        if (!cer) {
            return "";
        }
        //获取证书里的域名
        X509_NAME *name = X509_get_subject_name(cer);
        char ret[256] = {0};
        X509_NAME_get_text_by_NID(name, NID_commonName, ret, sizeof(ret));
        return ret;
    #else
        return "";
    #endif
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
