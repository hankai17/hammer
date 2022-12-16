//
// Created by root on 12/6/22.
//

#include "event_poller.hh"
#include "log.hh"

#include <string.h>

#define EPOLL_SIZE 5000

#define toEpollEvent(event)      (((event) & READ) ? EPOLLIN : 0) \
                               | (((event) & WRITE) ? EPOLLOUT : 0) \
                               | (((event) & ERROR) ? (EPOLLHUP | EPOLLERR) : 0) \
                               | (((event) & EP_LT) ? 0 : EPOLLET)
#define toEvent(epoll_event)     (((epoll_event) & EPOLLIN) ? READ : 0) \
                               | (((epoll_event) & EPOLLOUT) ? WRITE : 0) \
                               | (((epoll_event) & EPOLLHUP) ? ERROR : 0) \
                               | (((epoll_event) & EPOLLERR) ? ERROR : 0) \

namespace hammer {
    static Logger::ptr g_logger = HAMMER_LOG_NAME("system");

    EventPoller::EventPoller(const std::string &name) :
            m_name(name) {
        m_wakeup_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        HAMMER_ASSERT(m_wakeup_fd >= 0);
        m_epoll_fd = epoll_create(EPOLL_SIZE); 
        HAMMER_ASSERT(m_epoll_fd > 0);
		m_thread_id = std::this_thread::get_id();
        if (addEvent(m_wakeup_fd, READ, [this](int event){ onPipeEvent(); }) != 0) {
            HAMMER_LOG_WARN(g_logger) << "EventPoller add wakeup_fd failed: " << strerror(errno);
        }
    }

    EventPoller::~EventPoller() {
        // TODO
    }

    MBuffer::ptr EventPoller::getSharedBuffer() {
        auto ret = m_shared_buffer.lock();
        if (!ret) {
            ret = std::make_shared<MBuffer>();
            m_shared_buffer = ret;
        }
        return ret;
    }

    Task::ptr EventPoller::async_l(TaskIn task, bool first) {
        if (isCurrentThread()) {
            task();
            return nullptr;
        }
        auto ret = std::make_shared<Task>(std::move(task));
        {
            std::lock_guard<std::mutex> lock(m_task_mutex);
            if (first) {
                m_task_list.emplace_front(ret);
            } else {
                m_task_list.emplace_back(ret);
            }
        }
        uint64_t counter = 1;
        write(m_wakeup_fd, &counter, sizeof(uint64_t));
        return ret;
    }

    Task::ptr EventPoller::async(TaskIn task) {
        return async_l(std::move(task), false);
    }

    Task::ptr EventPoller::async_first(TaskIn task) {
        return async_l(std::move(task), true);
    }

    void EventPoller::onPipeEvent() {
        uint64_t counter;
        read(m_wakeup_fd, &counter, sizeof(uint64_t));
        decltype(m_task_list) task_list;
        {
            std::lock_guard<std::mutex> lock(m_task_mutex);
            m_task_list.swap(task_list);
        }
        task_list.for_each([&](const Task::ptr &task) {
            try {
                (*task)();
            } catch (ExitException &) {
                m_exit_flag = true;
            } catch (std::exception &e) {
                HAMMER_LOG_WARN(g_logger) << "Exception occurred when do async task: " << e.what();
            }
        });
    }

    int EventPoller::addEvent(int fd, int event, PollEventCB cb) {
        HAMMER_ASSERT(cb);
        if (isCurrentThread()) {
		    epoll_event ev = {0};
            ev.events = toEpollEvent(event);
            ev.data.fd = fd;
            int ret = epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &ev);
            if (ret == 0) {
                m_event_map.emplace(fd, std::make_shared<PollEventCB>(std::move(cb)));
            }
            return ret;
        }
        async([this, fd, event, cb]() {
            addEvent(fd, event, std::move(cb));
        });
        return 0;
    }

    int EventPoller::delEvent(int fd, PollEventCB cb) {
        if (isCurrentThread()) {
            int ret = epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
            if (ret == 0 && m_event_map.erase(fd) > 0) {
                if (cb) {
                    cb(ret); 
                }
            }
            return ret;
        }
        async([this, fd, cb]() {
            delEvent(fd, std::move(cb));
        });
        return 0;
    }

    int EventPoller::modEvent(int fd, int event, PollEventCB cb) {
        epoll_event ev = {0};
        ev.events = toEpollEvent(event);
        ev.data.fd = fd;
        return epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    }

    uint64_t EventPoller::updateTimer(uint64_t now) {
        decltype(m_timer_map) timer_map;
        m_timer_map.swap(timer_map);
        for (auto it = timer_map.begin(); it != timer_map.end() && it->first <= now;) {
            try {
                uint64_t next_time = (*(it->second))();
                if (next_time) {
                    m_timer_map.emplace(next_time + now, std::move(it->second));
                }
                it = timer_map.erase(it); 
            } catch (std::exception &e) {
                HAMMER_LOG_WARN(g_logger) << "Exception occurred when do update Timer: " << e.what();
            }
        }
        timer_map.insert(m_timer_map.begin(), m_timer_map.end());
        timer_map.swap(m_timer_map);
        auto it = m_timer_map.begin();
        if (it == m_timer_map.end()) {
            return 0;
        }
        return it->first - now;
    }

    uint64_t EventPoller::getNextTimer() {
        auto it = m_timer_map.begin();
        if (it == m_timer_map.end()) {
            return 0;
        }
        uint64_t now = getCurrentMillSecond();
        if (it->first > now) {
            return it->first - now;
        }
        return updateTimer(now); 
    }

    EventPoller::TimerTask::ptr EventPoller::doTimerTask(uint64_t ms, std::function<uint64_t(void)> task) {
        EventPoller::TimerTask::ptr ret = std::make_shared<TimerTask>(std::move(task));
        uint64_t timer_deadline = getCurrentMillSecond() + ms; 
        async_first([timer_deadline, ret, this]() {
            m_timer_map.emplace(timer_deadline, ret);
        });
        return ret;
    }

    void EventPoller::runLoop(bool blocked) {
        if (!blocked) {
            m_loop_thread = new std::thread(&EventPoller::runLoop, this, true);
            m_sem_loop_thread_started.wait();
            return;
        }
		m_thread_id = std::this_thread::get_id();
        m_sem_loop_thread_started.notify();

        m_exit_flag = false;
        uint64_t next_time = 0;
        struct epoll_event events[EPOLL_SIZE];
        while (!m_exit_flag) {
            next_time = getNextTimer();
            int ret = epoll_wait(m_epoll_fd, events, EPOLL_SIZE, next_time ? next_time : -1);
            if (ret <= 0) {
                continue;
            }
            for (int i = 0; i < ret; i++) {
                struct epoll_event &ev = events[i];
                int fd = ev.data.fd;
                auto it = m_event_map.find(fd);
                if (it == m_event_map.end()) {
                    epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
                    continue;
                }
                auto cb = it->second;
                try {
                    (*cb)(toEvent(ev.events));
                } catch (std::exception &e) {
                    HAMMER_LOG_WARN(g_logger) << "Exception occurred when do epoll_wait cb: " << e.what();
                }
            }
        }
    }
    
    void EventPoller::shutdown() {
        async_l([]() {
            throw ExitException();
        }, false);
    }

    
    size_t TaskExecutorManager::addPoller(const std::string &name, size_t size) {
        auto cpus = std::thread::hardware_concurrency();
        size = size > 0 ? size : cpus;
        for (size_t i = 0; i < size; i++) {
            auto full_name = name + "-" + std::to_string(i);
            EventPoller::ptr poller(new EventPoller(full_name));
            poller->runLoop(false);
            poller->async([full_name]() {
                pthread_setname_np(pthread_self(), full_name.substr(0, 15).c_str());
            });
            m_threads.emplace_back(std::move(poller));
        }
        return size;
    }

}
