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

    /*
    class TaskExecInterface {
    public:
        typedef std::shared_ptr<TaskExecInterface> ptr;
        TaskExecInterface() = default;
        virtual ~TaskExecInterface() = default;

        virtual Task::ptr async(TaskIn task) = 0;
        Task::ptr async_first(TaskIn task) {
            return async(std::move(task));
        }
        void sync(const TaskIn &task) {
            semaphore sem;
            auto ret = async([&]() {
                hammer::OnceToken(nullptr, [&](){
                    sem.post();
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
                    sem.post();
                }); 
                task();
            });
            if (ret && *ret) {
                sem.wait();
            }
        }
    };
    */

    class EventPoller {
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
        
        Task::ptr async_l(TaskIn task, bool first = false);
        Task::ptr async(TaskIn task);
        Task::ptr async_first(TaskIn task);
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
        std::multimap<uint64_t, TimerTask::ptr> m_timer_map;
        std::unordered_map<int, std::shared_ptr<PollEventCB>> m_event_map;
    };

    class TaskExecutor {
    public:
        using ptr = std::shared_ptr<TaskExecutor>;
        TaskExecutor() = default;
        ~TaskExecutor() = default;

        size_t getExecutorSize() const { return m_threads.size(); }
        
    protected:
        size_t addPoller(const std::string &name, size_t size);
        std::vector<EventPoller::ptr>   m_threads;
    private:
    };

    class EventPollerPool {
    public:
        using ptr = std::shared_ptr<EventPollerPool>;
        ~EventPollerPool() = default;
        static void setPoolSize(size_t size = 0);
    private:
        static size_t       s_pool_size;
    };

}

#endif //HAMMER_EVENT_POLLER_HH
