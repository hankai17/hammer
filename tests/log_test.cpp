//
// Created by root on 12/6/22.
//

#include "hammer/log.hh"
#include "hammer/util.hh"
#include "hammer/event_poller.hh"

static hammer::Logger::ptr g_root_logger = HAMMER_LOG_NAME("root");
static hammer::Logger::ptr g_system_logger = HAMMER_LOG_NAME("system");

int log_test()
{
    HAMMER_LOG_DEBUG(g_root_logger) << "root logger";
    HAMMER_LOG_DEBUG(g_system_logger) << "system logger";
    return 0;
}

void before_func()
{
    HAMMER_LOG_DEBUG(g_root_logger) << "before func";
}

void after_func()
{
    HAMMER_LOG_DEBUG(g_root_logger) << "after func";
}

int after_func_arg(int a)
{
    HAMMER_LOG_DEBUG(g_root_logger) << "after func" << a;
    return 0;
}

void once_test()
{
    hammer::OnceToken once(nullptr, after_func);
    hammer::OnceToken once1(before_func, after_func);
    hammer::OnceToken once2(before_func, std::bind(after_func_arg, 2));
}

void timer_test()
{
    while (1) {
        HAMMER_LOG_DEBUG(g_root_logger) << "getCurrentMillSecond: " << hammer::getCurrentMillSecond();
        HAMMER_LOG_DEBUG(g_root_logger) << "getCurrentMicrSecond: " << hammer::getCurrentMicroSecond();
        HAMMER_LOG_DEBUG(g_root_logger) << "getCurrentMillSecond sys: " << hammer::getCurrentMillSecond(true);
        HAMMER_LOG_DEBUG(g_root_logger) << "getCurrentMicrSecond sys: " << hammer::getCurrentMicroSecond(true);
        sleep(1);
    }
}

int task_fun(char c, int i) {
    sleep(2);
    HAMMER_LOG_DEBUG(g_root_logger) << "c: " << c << ", i: " << i;
    return 0;
}

void task_test()
{
    hammer::TaskImp<int(char, int)> task(task_fun);
    //task.cancel();
    task('x', 0);
    HAMMER_LOG_DEBUG(g_root_logger) << "task done";
}

int main()
{
    task_test();
    return 0;
}
