//
// Created by root on 12/6/22.
//

#include "hammer/log.hh"
#include "hammer/util.hh"
#include "hammer/event_poller.hh"
#include "hammer/tcp_server.hh"

static hammer::Logger::ptr g_root_logger = HAMMER_LOG_NAME("root");

hammer::EventPoller::ptr g_poller = nullptr;

uint64_t timer_cb()
{
    HAMMER_LOG_WARN(g_root_logger) << "timer cb";
    //return 0;
    return 1000 * 1;
}

int timer_test()
{
    g_poller = std::make_shared<hammer::EventPoller>("hammer");
    g_poller->doTimerTask(1000 * 2, timer_cb);
    g_poller->runLoop(true);
    return 0;
}

void obj_release_test()
{
#if 0
    std::shared_ptr<int> s = std::make_shared<int>(1);
#else
    std::shared_ptr<uint8_t> s = nullptr; 
    s.reset(new uint8_t[8], [](uint8_t* ptr) {
        HAMMER_LOG_WARN(g_root_logger) << "delete ~s";
        delete[] ptr;
    });
#endif
    //HAMMER_LOG_WARN(g_root_logger) << "1s.use_count: " << s.use_count();

    g_poller->async([s=std::move(s)]() {
        HAMMER_LOG_WARN(g_root_logger) << "fun_obj";
        //HAMMER_LOG_WARN(g_root_logger) << "s.use_count: " << s.use_count();
    });
    //HAMMER_LOG_WARN(g_root_logger) << "2s.use_count: " << s.use_count();
}

int poller_test()
{
    g_poller = std::make_shared<hammer::EventPoller>("hammer");
    g_poller->runLoop(false);

    for (int i = 0; i < 1000000; i++) {
        obj_release_test();
    }

    return 0;
}

int main()
{
    poller_test();
    while(1) { sleep(1); }
    return 0;
}
