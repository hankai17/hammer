//
// Created by root on 12/6/22.
//

#include "hammer/log.hh"

static hammer::Logger::ptr g_root_logger = SYLAR_LOG_NAME("root");
static hammer::Logger::ptr g_system_logger = SYLAR_LOG_NAME("system");

int main()
{
    SYLAR_LOG_DEBUG(g_root_logger) << "root logger";
    SYLAR_LOG_DEBUG(g_system_logger) << "system logger";
    return 0;
}

