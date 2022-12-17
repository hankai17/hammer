//
// Created by root on 12/6/22.
//

#include "hammer/log.hh"
#include "hammer/util.hh"
#include "hammer/event_poller.hh"

static hammer::Logger::ptr g_root_logger = HAMMER_LOG_NAME("root");

hammer::EventPoller::ptr g_poller = nullptr;

uint64_t timer_cb()
{
    HAMMER_LOG_DEBUG(g_root_logger) << "timer cb";
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

int poller_test()
{
    g_poller = std::make_shared<hammer::EventPoller>("hammer");
    g_poller->runLoop(false);
    g_poller->doTimerTask(1000 * 2, timer_cb);
    return 0;
}

int poller_pool_test()
{
    //hammer::Singleton<hammer::EventPollerPool>::instance();
    for (int i = 0; i < 8; i++) {
        hammer::Singleton<hammer::EventPollerPool>::instance().getExecutor()->async([i](){
            HAMMER_LOG_DEBUG(g_root_logger) << i << " normal cb";
        });
    }
    return 0;
}

int main()
{
    //poller_test();
    poller_pool_test();
    while(1) { sleep(1); }
    return 0;
}
