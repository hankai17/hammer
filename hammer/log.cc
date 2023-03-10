//
// Created by root on 12/1/19.
//

#include "log.hh"
#include <map>
#include <iostream>
#include <functional>
#include <time.h>
#include <string.h>

namespace hammer {

    const char* LogLevel::ToString(LogLevel::Level level) {
        switch (level) {
#define XX(name) \
            case LogLevel::name: \
                return #name; \
                break;
            XX(DEBUG);
            XX(INFO);
            XX(WARN);
            XX(ERROR);
            XX(FATAL);
#undef XX
            default:
                return "UNKNOWN";
        }
        return "UNKNOWN";
    }

    LogLevel::Level LogLevel::FromString(const std::string& val) { // !!!
#define XX(level, v) \
    if (val == #v) { \
        return LogLevel::level; \
    }

        XX(DEBUG, DEBUG);
        XX(INFO, INFO);
        XX(WARN, WARN);
        XX(ERROR, ERROR);
        XX(FATAL, FATAL);
        XX(DEBUG, debug);
        XX(INFO, info);
        XX(WARN, warn);
        XX(ERROR, error);
        XX(FATAL, fatal);
#undef XX
        return LogLevel::UNKNOW;
    }

    LogEvent::LogEvent(uint64_t time, LogLevel::Level level, const char* file, uint32_t line,
                       uint32_t tid)
            :m_time(time),
             m_level(level),
             m_file(file),
             m_line(line),
             m_threadId(tid) {
    }

    void LogEvent::format(const char* fmt, ...) {
        va_list al;
        va_start(al, fmt);
        format(fmt, al);
        va_end(al);
    }

    void LogEvent::format(const char* fmt, va_list al) {
        char* buf = nullptr;
        int len = vasprintf(&buf, fmt, al);
        if (len != -1) {
            m_ss << std::string(buf, len);
            free(buf);
        }
    }

    class NameFormatItem : public LogFormatter::FormatItem {
    public:
        NameFormatItem(const std::string &str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << logger->getName();
        }
    };

    class LevelFormatItem : public LogFormatter::FormatItem {
    public:
        LevelFormatItem(const std::string &str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << LogLevel::ToString(level);
        }
    };

    class FilenameFormatItem : public LogFormatter::FormatItem {
    public:
        FilenameFormatItem(const std::string& str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << event->getFile();
        }
    };

    class DataTimeFormatItem : public LogFormatter::FormatItem {
    public:
        DataTimeFormatItem(const std::string& str = "%Y-%m-%d %H:%M:%S")
                : m_format(str) {
            if (m_format.empty()) {
                m_format = "%Y-%m-%d %H:%M:%S";
            }
        }
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            struct tm tm;
            time_t time = event->getTime();
            localtime_r(&time, &tm);
            char buf[64];
            strftime(buf, sizeof(buf), m_format.c_str(), &tm);
            //os << buf;
            //os << std::to_string(getCurrentMillSecond(true));
            os << std::to_string(getCurrentMicroSecond(true));
        }
    private:
        std::string m_format;
    };

    class LineFormatItem : public LogFormatter::FormatItem {
    public:
        LineFormatItem(const std::string& str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << event->getLine();
        }
    };

    class ThreadIdFormatItem : public LogFormatter::FormatItem {
    public:
        ThreadIdFormatItem(const std::string& str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << event->getThreadId();
        }
    };

    class MessageFormatItem : public LogFormatter::FormatItem {
    public:
        MessageFormatItem(const std::string& str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << event->getContent();
        }
    };

    class NewLineFormatItem : public LogFormatter::FormatItem {
    public:
        NewLineFormatItem(const std::string& str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << std::endl;
        }
    };

    class TabFormatItem : public LogFormatter::FormatItem {
    public:
        TabFormatItem(const std::string& str = "") {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << "\t";
        }
    };

    class StringFormatItem : public LogFormatter::FormatItem {
    public:
        StringFormatItem(const std::string& str)
                : m_string(str) {}
        void format(std::ostream &os, Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
            os << m_string;
        }
    private:
        std::string m_string;
    };

    std::string LogFormatter::format(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
        std::stringstream ss;
        for (auto&i : m_items) {
            i->format(ss, logger, level, event);
            //std::cout<< "debug log, " << ss.str() << std::endl;
        }
        return ss.str();
    }

    LogFormatter::LogFormatter(const std::string& pattern)
            : m_pattern(pattern) {
        init();
    }

    void StdoutLogAppender::log(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
        if (level >= m_level) {
            std::cout << m_formatter->format(logger, level, event);
        }
    }

    FileLogAppender::FileLogAppender(const std::string& filename)
            :m_filename(filename) {
        reopen();
    }

    void FileLogAppender::log(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) {
        if (level >= m_level) {
            uint64_t now = time(0);
            if (now != m_lastTime) {
                reopen();
                m_lastTime = now;
            }
            std::lock_guard<std::mutex> lock(m_mutex);
            m_filestream << m_formatter->format(logger, level, event);
            m_filestream.flush();
        }
    }

    bool FileLogAppender::reopen() {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_filestream) {
            m_filestream.close();
        }
        m_filestream.open(m_filename, std::ios::app);
        return !!m_filestream;
    }

    void Logger::addAppender(LogAppender::ptr appender) {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (!appender->getFormatter()) {
            appender->setFormatter(m_formatter);
            appender->setLevel(m_level);
        }
        m_appenders.push_back(appender);
    }

    void Logger::delAppender(LogAppender::ptr appender) {
        std::lock_guard<std::mutex> lock(m_mutex);
        for (auto it = m_appenders.begin(); it != m_appenders.end(); it++) {
            if (*it == appender) {
                m_appenders.erase(it);
                break;
            }
        }
        /*
        for (auto it = m_appenders.begin(); it != m_appenders.end();) {
            if (*it == appender) {
                m_appenders.erase(it++);
                break;
            } else {
                it++;
            }
        }
         */
    }

    Logger::Logger(const std::string& name)
            : m_name(name),
              m_level(LogLevel::DEBUG) {
        m_formatter.reset(new LogFormatter("%d{%Y-%m-%d %H:%M:%S}%T%t%T[%p]%T[%c]%T%f:%l%T%m%n"));
    }

    void Logger::log(LogLevel::Level level, LogEvent::ptr event) {
        if (level >= m_level) {
            std::lock_guard<std::mutex> lock(m_mutex);
            for (auto&i : m_appenders) {
                i->log(shared_from_this(), event->getLevel(), event);
            }
        }
    }

    void LogFormatter::init() {
        std::vector<std::tuple<std::string, std::string, int> > vec;
        enum parse_stat { // Do not design deeply
            INIT = 0,
            ITEM = 1,
            FORM = 2,
            NORM = 3,
        };

        std::string item;
        std::string format;
        char* format_s = nullptr;
        char* format_e = nullptr;
        parse_stat curr_state = INIT;

        for (size_t i = 0; i < m_pattern.size(); i++) {
            switch(curr_state) {
                case INIT:
                    if (m_pattern[i] == '%') {
                        curr_state = ITEM;
                    } else {
                        curr_state = INIT;
                    }
                    break;
                case ITEM:
                    if (m_pattern[i] /*&& not space*/) {
                        if (item == "") {
                            item = m_pattern[i];
                            if ( i + 1 < m_pattern.size() && m_pattern[i + 1] != '{') {
                                vec.push_back(std::make_tuple(item, format, 1));
                                item = "";
                                format = "";
                                curr_state = INIT;
                            } else if (i + 1 < m_pattern.size() && m_pattern[i + 1] == '{') {
                                format_s = &m_pattern[i + 1];
                                curr_state =  FORM;
                            } else if ( i == m_pattern.size() - 1) {
                                vec.push_back(std::make_tuple(item, format, 1));
                                item = "";
                                format = "";
                                curr_state = INIT;
                            }
                            if (i + 1 < m_pattern.size() &&
                                (m_pattern[i + 1] == '[' || m_pattern[i + 1] == ']' || m_pattern[i + 1] == ':') ) { //special str: []
                                curr_state = NORM;
                            }
                        }
                        break;
                    }
                    break;
                case FORM:
                    if (m_pattern[i] == '}') {
                        format_e = &m_pattern[i];
                        format = std::string(format_s + 1, format_e - format_s - 1);
                        vec.push_back(std::make_tuple(item, format, 1));
                        item = "";
                        format = "";
                        curr_state = INIT;
                    }
                    break;
                case NORM:
                    vec.push_back(std::make_tuple(std::string(&m_pattern[i], 1), format, 0));
                    item = "";
                    format = "";
                    curr_state = INIT;
                    break;
                default:
                    break;
            }
        }

        static std::map<std::string, std::function<FormatItem::ptr(const std::string& str)> > s_format_items = {
#define XX(str, C) \
        {#str, [](const std::string& fmt) { return FormatItem::ptr (new C(fmt)); }}

                XX(m, MessageFormatItem),
                XX(p, LevelFormatItem),
                XX(c, NameFormatItem),
                XX(t, ThreadIdFormatItem),
                XX(n, NewLineFormatItem),
                XX(d, DataTimeFormatItem),
                XX(f, FilenameFormatItem),
                XX(l, LineFormatItem),
                XX(T, TabFormatItem),
#undef XX
        };

        for (auto& i : vec) {
            //std::cout << "+++" << std::get<0>(i) << " : " << std::get<1>(i) << std::endl;
            if (std::get<2>(i) == 0) {
                m_items.push_back(FormatItem::ptr(new StringFormatItem(std::get<0>(i)))); // "["
            } else {
                auto it = s_format_items.find(std::get<0>(i));
                if (it != s_format_items.end()) {
                    m_items.push_back(it->second(std::get<1>(i)));
                } else {
                    m_items.push_back(FormatItem::ptr(new StringFormatItem("<<error format %" + std::get<0>(i) + ">>")));
                }
            }
        }
    }

    LogEventWrap::LogEventWrap(hammer::Logger::ptr logger, hammer::LogEvent::ptr event)
            :m_logger(logger),
             m_event(event) {
    }

    LogEventWrap::~LogEventWrap() {
        m_logger->log(m_logger->getLevel(), m_event);
    }

    LoggerManager::LoggerManager() {
        m_root.reset(new Logger("root"));
        m_root->addAppender(LogAppender::ptr(new StdoutLogAppender));
        GetMap()[m_root->getName()] = m_root;

        m_system.reset(new Logger("system"));
        //m_system->addAppender(LogAppender::ptr(new FileLogAppender("./1.log")));
        m_system->addAppender(LogAppender::ptr(new  StdoutLogAppender));
        GetMap()[m_system->getName()] = m_system;
    }

    Logger::ptr LoggerManager::getLogger(const std::string& name) {
        auto it = GetMap().find(name);
        if (it != GetMap().end()) {
            return it->second;
        }
        //return nullptr;
        Logger::ptr logger(new Logger(name));
        GetMap()[name] = logger;
        logger->addAppender(LogAppender::ptr(new StdoutLogAppender));
        return logger;
    }

}
