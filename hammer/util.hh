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

#define HAMMER_ASSERT(x) \
    if (!(x)) { \
        HAMMER_LOG_ERROR(HAMMER_LOG_ROOT()) << "ASSERTION: " #x \
        << "\nbacktrace:\n" \
        << hammer::BacktraceToString(100, 2, "    "); \
        assert(x); \
    }

namespace hammer {

    int GetThreadId();
    void setThreadName(const std::string &name);
    void Backtrace(std::vector<std::string> &bt, int size, int skip = 1);
    std::string BacktraceToString(int size = 64, int skip = 2, const std::string& prefix = " ");

    class semaphore {
    public:
        explicit semaphore(size_t initial = 0) {
            sem_init(&m_sem, 0, initial);
        }
        ~semaphore() {
            sem_destroy(&m_sem);
        }
        void post(size_t n = -1) {
            while (n--) {
                sem_post(&m_sem);
            }
        }
        void wait() {
            sem_wait(&m_sem);
        }
    private:
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
        void for_each(FUNC &&func) {
            for (auto &t : *this) {
                func(t);
            }
        }
        template<typename FUNC>
        void for_each(FUNC &&func) const {
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

	void no_locks_localtime(struct tm *tmp, time_t t);
	void local_time_init();
	int get_daylight_active();
	uint64_t getCurrentMillSecond(bool system_time = false);
	uint64_t getCurrentMicroSecond(bool system_time = false);
    
}

#endif //HAMMER_UTIL_HH
