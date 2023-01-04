//
// Created by root on 12/6/22.
//

#ifndef HAMMER_EVENT_POLLER_HH
#define HAMMER_EVENT_POLLER_HH

#include <memory>
#include <map>
#include <unordered_map>
#include <functional>
#include <string>
#include <sys/epoll.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <mutex>

#include "hammer/util.hh"
#include "hammer/singleton.hh"
#include "hammer/mbuffer.hh"

namespace hammer {

    template<typename First, typename... Rest>
    class TaskImp;
    
    template<typename First, typename... Rest>
    class TaskImp<First(Rest...)> {
    public:
        using ptr = std::shared_ptr<TaskImp>;
        using func_type = std::function<First(Rest...)>;
        ~TaskImp() = default;

        template<typename FUNC>
        TaskImp(FUNC &&task) {
            m_strong_task = std::make_shared<func_type>(std::forward<FUNC>(task));
            m_weak_task = m_strong_task;
        }

        void cancel() { m_strong_task = nullptr; }
        operator bool() { return m_strong_task && *m_strong_task; }

        template<typename T>
        static typename std::enable_if<std::is_void<T>::value, void>::type
        default_value() {}

        template<typename T>
        static typename std::enable_if<std::is_pointer<T>::value, T>::type
        default_value() { return nullptr; }

        template<typename T>
        static typename std::enable_if<std::is_integral<T>::value, T>::type
        default_value() { return 0; }

        First operator()(Rest ...args) const {
            auto strong_task = m_weak_task.lock();
            if (strong_task && *strong_task) {
                return (*strong_task)(std::forward<Rest>(args)...);
            }
            return default_value<First>();
        }

    protected:
        std::weak_ptr<func_type>    m_weak_task;
        std::shared_ptr<func_type>  m_strong_task;
    };

    using TaskIn = std::function<void()>;
    using Task = TaskImp<void()>;

    class TaskExecutor {
    public:
        using ptr = std::shared_ptr<TaskExecutor>;
        TaskExecutor() = default;
        virtual ~TaskExecutor() = default;

        virtual Task::ptr async(TaskIn task) = 0;
        virtual Task::ptr async_first(TaskIn task) { return async(std::move(task)); }
        void sync(const TaskIn &task) {
            semaphore sem;
            auto ret = async([&]() {
                hammer::OnceToken(nullptr, [&](){
                    sem.notify();
                });
                task();
            });
            if (ret && *ret) {
                sem.wait();
            }
        }
        void sync_first(const TaskIn &task) {
            semaphore sem;
            auto ret = async_first([&]() {
                hammer::OnceToken(nullptr, [&](){
                    sem.notify();
                });
                task();
            });
            if (ret && *ret) {
                sem.wait();
            }
        }
    };

    class EventPoller : public TaskExecutor,
            public std::enable_shared_from_this<EventPoller> {
    public:
        using ptr = std::shared_ptr<EventPoller>;
        using PollEventCB = std::function<void(int event)>;
        using TimerTask = TaskImp<uint64_t(void)>;

        enum Event : uint64_t {
            NONE    = 0,
            READ    = 1,
            WRITE   = 2,
            ERROR   = 4,
            EP_LT   = 8,
        };

        EventPoller(const std::string &name);
        ~EventPoller();
        const std::string &getName() const { return m_name; }
        std::thread::id getThreadId() const { return m_thread_id; }
        bool isCurrentThread() { return m_thread_id == std::this_thread::get_id(); }
        MBuffer::ptr getSharedBuffer();
        static EventPoller::ptr getCurrentPoller();
        
        Task::ptr async_l(TaskIn task, bool first = false);
        Task::ptr async(TaskIn task) override;
        Task::ptr async_first(TaskIn task) override;
        void onPipeEvent();
        
        int addEvent(int fd, int event, PollEventCB cb);
        int delEvent(int fd, PollEventCB cb = nullptr);
        int modEvent(int fd, int event, PollEventCB cb = nullptr);
    
        uint64_t updateTimer(uint64_t now);
        uint64_t getNextTimer();
        TimerTask::ptr doTimerTask(uint64_t ms, std::function<uint64_t(void)> task);
            
        void runLoop(bool blocked);
        void shutdown();

    private:
        class ExitException : public std::exception {};
    private:
        std::string         m_name = "";
        int                 m_epoll_fd = -1;
        int                 m_wakeup_fd = -1;
        std::thread::id     m_thread_id;
        bool                m_exit_flag = false;
        std::mutex          m_task_mutex;
        List<Task::ptr>     m_task_list;
        std::thread        *m_loop_thread = nullptr;
        semaphore           m_sem_loop_thread_started;
        std::weak_ptr<MBuffer>                  m_shared_buffer;
        std::multimap<uint64_t, TimerTask::ptr> m_timer_map;
        std::unordered_map<int, std::shared_ptr<PollEventCB>> m_event_map;
    };

    class Timer {
    public:
        using ptr = std::shared_ptr<Timer>;
        Timer(uint64_t ms, const std::function<bool()> &cb, const EventPoller::ptr &poller) :
            m_poller(poller) {
            if (!m_poller) {
                // TODO when use multi-thread
            }
            m_timer = m_poller->doTimerTask(ms, [ms, cb]() -> uint64_t {
                try {
                    if (cb()) {
                        return ms;
                    }
                    return 0;
                } catch (std::exception &e) {
                    return ms;
                }
            });
        }
        ~Timer() {
            auto timer = m_timer.lock();
            if (timer) {
                timer->cancel();
            }
        }
    private:
        EventPoller::ptr                        m_poller;
        std::weak_ptr<EventPoller::TimerTask>   m_timer;
    };

    class TaskExecutorManager {
    public:
        using ptr = std::shared_ptr<TaskExecutorManager>;
        TaskExecutorManager() = default;
        virtual ~TaskExecutorManager() = default;

        size_t getExecutorSize() const { return m_threads.size(); }
        TaskExecutor::ptr getExecutor() { return m_threads[m_thread_pos++ % m_threads.size()]; }
        void getExecutorDelay(const std::function<void(const std::vector<int>&)> &cb) {}
        void for_each(const std::function<void(const TaskExecutor::ptr &)> &cb) {
            for (auto &ep : m_threads) {
                cb(ep);
            }
        }

    protected:
        size_t addPoller(const std::string &name, size_t size);
        size_t                          m_thread_pos = 0;
        std::vector<EventPoller::ptr>   m_threads;
    private:
    };

    class EventPollerPool : public TaskExecutorManager,
            public std::enable_shared_from_this<EventPollerPool> {
    public:
        using ptr = std::shared_ptr<EventPollerPool>;
        EventPollerPool() { addPoller("event poller", m_pool_size); }
        ~EventPollerPool() override = default;
        void setPoolSize(size_t size = 0) { m_pool_size = size; }
        EventPoller::ptr getFirstPoller() { return std::dynamic_pointer_cast<EventPoller>(m_threads.front()); }
        EventPoller::ptr getPoller(bool prefer_current_poller = true) {
            auto poller = EventPoller::getCurrentPoller();
            if (prefer_current_poller && poller) {
                return poller;
            }
            return std::dynamic_pointer_cast<EventPoller>(getExecutor());
        }
    private:
        size_t       m_pool_size = 0;
    };

    class WorkThreadPool : public TaskExecutorManager,
            public std::enable_shared_from_this<WorkThreadPool> {
    public:
        using ptr = std::shared_ptr<WorkThreadPool>;
        WorkThreadPool() { addPoller("work poller", m_pool_size); }
        ~WorkThreadPool() override = default;
        void setPoolSize(size_t size = 0) { m_pool_size = size; }
        EventPoller::ptr getFirstPoller() { return std::dynamic_pointer_cast<EventPoller>(m_threads.front()); }
        EventPoller::ptr getPoller() { return std::dynamic_pointer_cast<EventPoller>(getExecutor()); }
    private:
        size_t  m_pool_size = 0;
    };

}

#endif //HAMMER_EVENT_POLLER_HH
