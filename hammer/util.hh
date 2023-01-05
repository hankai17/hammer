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
}

#endif //HAMMER_UTIL_HH
