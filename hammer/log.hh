//
// Created by root on 12/1/19.
//

#ifndef HAMMER_LOG_HH
#define _HAMMER_LOG_HH

#include <string>
#include <stdint.h>
#include <memory>
#include <list>
#include <mutex>
#include <sstream>
#include <fstream>
#include <vector>
#include <stdarg.h>
#include <map>
#include <yaml-cpp/yaml.h>
#include <iostream>

#include "singleton.hh"
#include "util.hh"

#define HAMMER_LOG_LEVEL(logger, level) \
    if (logger->getLevel() <= level) \
        hammer::LogEventWrap(logger, \
                hammer::LogEvent::ptr(new hammer::LogEvent(time(0), level, __FILE__, __LINE__, hammer::GetThreadId()))).getSS()

#define HAMMER_LOG_DEBUG(logger) HAMMER_LOG_LEVEL(logger, hammer::LogLevel::DEBUG)
#define HAMMER_LOG_INFO(logger) HAMMER_LOG_LEVEL(logger, hammer::LogLevel::INFO)
#define HAMMER_LOG_WARN(logger) HAMMER_LOG_LEVEL(logger, hammer::LogLevel::WARN)
#define HAMMER_LOG_ERROR(logger) HAMMER_LOG_LEVEL(logger, hammer::LogLevel::ERROR)

#define HAMMER_LOG_FMT_LEVEL(logger, level, fmt, ...) \
    if (logger->getLevel() <= level) \
        hammer::LogEventWrap(logger, \
        hammer::LogEvent::ptr(new hammer::LogEvent(time(0), level, __FILE__, __LINE__, hammer::GetThreadId())).getLogEvent()->format(fmt, __VA_ARGS__)

#define HAMMER_LOG_FMT_DEBUG(logger, fmt, ...) HAMMER_LOG_FMT_LEVEL(logger, hammer::LogLevel:DEBUG, fmt, ...)
#define HAMMER_LOG_FMT_INFO(logger, fmt, ...) HAMMER_LOG_FMT_LEVEL(logger, hammer::LogLevel:INFO, fmt, ...)
#define HAMMER_LOG_FMT_WARN(logger, fmt, ...) HAMMER_LOG_FMT_LEVEL(logger, hammer::LogLevel:WARN, fmt, ...)
#define HAMMER_LOG_FMT_ERROR(logger, fmt, ...) HAMMER_LOG_FMT_LEVEL(logger, hammer::LogLevel:ERROR, fmt, ...)

#define HAMMER_LOG_ROOT() hammer::Singleton<hammer::LoggerManager>::instance().getRoot()
#define HAMMER_LOG_NAME(name) hammer::Singleton<hammer::LoggerManager>::instance().getLogger(name)

namespace hammer {
    class Logger;
    class LogLevel {
    public:
        enum Level {
            UNKNOW  = 0,
            DEBUG   = 1,
            INFO    = 2,
            WARN    = 3,
            ERROR   = 4,
            FATAL   = 5
        };
       static const char* ToString(LogLevel::Level level);
       static LogLevel::Level FromString(const std::string& val);
    };

    class LogEvent {
    public:
        typedef std::shared_ptr<LogEvent> ptr;
        LogEvent(uint64_t time, LogLevel::Level level, const char* file, uint32_t line, uint32_t tid);
        uint64_t getTime() const { return m_time; }
        LogLevel::Level getLevel() const { return m_level; }
        const char* getFile() const { return m_file; }
        uint32_t getLine() const { return m_line; }
        uint32_t getThreadId() const { return m_threadId; }
        uint32_t getFiberId() const { return m_fiberId; }
        std::stringstream& getSS() { return m_ss; } // Why not const? Why return &?
        std::string getContent() const { return m_ss.str(); }

        void format(const char* fmt, ...); // Init ss
        void format(const char* fmt, va_list al);
    private:
        uint64_t m_time         = 0;
        LogLevel::Level         m_level;
        const char* m_file      = nullptr; // Why not string // Below vaule all from para
        uint32_t m_line         = 0;
        uint32_t m_threadId     = 0;
        uint32_t m_fiberId      = 0;
        std::stringstream       m_ss; // Why need this? We already had formatter
    };

    class LogFormatter { // This class used for log4j config
    public:
        typedef std::shared_ptr<LogFormatter> ptr;
        LogFormatter(const std::string& pattern);
        //std::string format(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event); // Out put log // Why not ???
        std::string format(std::shared_ptr<Logger> logger, LogLevel::Level level, std::shared_ptr<LogEvent> event); // Out put log
        std::string getFormatter() const { return m_pattern; }

        void setFormatter(const std::string &pattern) { m_pattern = pattern; }
        std::string toYamlString();
    public:
        class FormatItem {
        public:
            typedef std::shared_ptr<FormatItem> ptr;
            virtual ~FormatItem() {};
            virtual void format(std::ostream& os, std::shared_ptr<Logger> logger, LogLevel::Level level, std::shared_ptr<LogEvent> event) = 0; // Pure virtual func
        };
        void init();

    private:
        std::string m_pattern;
        std::vector<FormatItem::ptr> m_items;
    };

    class LogAppender { // Where to log
    public:
        typedef std::shared_ptr<LogAppender> ptr;
        virtual ~LogAppender() {}; // This class Must be publiced, so use virtual deconstruct

        void setFormatter(LogFormatter::ptr val) { m_formatter = val; }
        void setLevel(LogLevel::Level l) { m_level = l; }
        LogFormatter::ptr getFormatter() const { return m_formatter; }
        LogLevel::Level getLevel() const { return m_level; }
        virtual void log(std::shared_ptr<Logger> logger, LogLevel::Level level, LogEvent::ptr event) = 0;
        virtual std::string toYamlString() = 0;
        virtual std::string getType() = 0;
        virtual std::string getFile() = 0;
        virtual void setType(const std::string& type) = 0;
        virtual void setFile(const std::string& file) = 0;

    protected:
        LogLevel::Level     m_level;
        LogFormatter::ptr   m_formatter;
        std::string         m_type;
        std::string         m_file;
    };

    class Logger : public std::enable_shared_from_this<Logger> {
    public:
        typedef std::shared_ptr<Logger> ptr;
        //void log(LogLevel::Level level, const std::string& filename, uint32_t line_no, uint64_t m_time); // How to set formatter?  so ugly so enclosure a class
        void log(LogLevel::Level level, LogEvent::ptr event); // user how to use it. //Why ptr
        std::string getName() const { return m_name; }

        void setName(const std::string &name) { m_name = name; }
        LogLevel::Level getLevel() const { return m_level; }

        void setLevel(const LogLevel::Level &level) { m_level = level; }

        LogFormatter::ptr getFormatter() const { return m_formatter; }

        void addAppender(LogAppender::ptr appender);
        void delAppender(LogAppender::ptr appender);

        std::list<LogAppender::ptr> getAppender() const { return m_appenders; }
        Logger(const std::string& name = "root");

        std::string toYamlString() const;

        void clearAppender() { m_appenders.clear(); } //not const

    private:
        std::string                 m_name;
        LogLevel::Level             m_level;
        std::list<LogAppender::ptr> m_appenders; // Use ptr
        LogFormatter::ptr           m_formatter;
        std::mutex                  m_mutex;
    };

    class StdoutLogAppender : public LogAppender {
    public:
        typedef std::shared_ptr<StdoutLogAppender> ptr;
        void log(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) override;
        std::string toYamlString() override;
        std::string getType() override { return "StdoutLogAppender"; }
        std::string getFile() override { return ""; }
        void setType(const std::string& val) override { m_type = "StdoutLogAppender"; }
        void setFile(const std::string& val) override {}
    };

    class FileLogAppender : public LogAppender {
    public:
        typedef std::shared_ptr<FileLogAppender> ptr;

        FileLogAppender(const std::string& filename);
        void log(Logger::ptr logger, LogLevel::Level level, LogEvent::ptr event) override;
        std::string toYamlString() override;
        bool reopen();
        std::string getFilename() const { return m_filename; }
        std::string getType() override { return "FileLogAppender"; };
        std::string getFile() override { return m_filename; }
        void setType(const std::string& val) override { m_type = "FileLogAppender"; }
        void setFile(const std::string& val) override { m_filename = val; }

    private:
        std::string     m_filename;
        std::ofstream   m_filestream;
        std::mutex      m_mutex;
        uint64_t        m_lastTime;
    };

    class LogEventWrap { // a middle layer used to event and logger
    public:
        typedef std::shared_ptr<LogEventWrap> ptr;
        LogEventWrap(Logger::ptr logger, LogEvent::ptr event);
        LogEvent::ptr getLogEvent() const { return m_event; }
        std::stringstream& getSS() const { return m_event->getSS(); }
        ~LogEventWrap();

    private:
        Logger::ptr     m_logger;
        LogEvent::ptr   m_event;
    };

    class LoggerManager {
    public:
        typedef std::shared_ptr<LoggerManager> ptr;
        LoggerManager();
        Logger::ptr getLogger(const std::string& name);
        Logger::ptr getRoot() const { return m_root; }
        std::map<std::string, Logger::ptr> &GetMap() { return m_loggers; }
        ~LoggerManager() {
            /*
          for (const auto& i : GetMap()) {
            std::cout<< i.second.use_count() <<std::endl;
          }
             */
        }
    private:
        Logger::ptr                         m_root;
        Logger::ptr                         m_system;
        std::map<std::string, Logger::ptr> m_loggers;
    };

    class LoggerConfig {
    public:
        typedef std::shared_ptr<LoggerConfig> ptr;

        std::string toYamlString() const {
            YAML::Node node;
            node["name"] = m_log_name;
            node["level"] = LogLevel::ToString(m_level);
            node["formatter"] = m_formatter;
            for (const auto& i : m_appenders) {
                node["appender"].push_back(YAML::Load(i->toYamlString())); // not node.push_back(YAML::Load(i->toYamlString))
            }
            std::stringstream ss;
            ss << node;
            return ss.str();
        }

        void setDefaultRoot();

        LoggerConfig(const std::string &root = "") { if (root == "root") setDefaultRoot(); }
        std::string getLogName() const { return m_log_name; }
        void setLogName(const std::string& log_name) { m_log_name = log_name; }
        LogLevel::Level getLogLevel() const { return m_level; }
        void setLogLevel(const LogLevel::Level& level) { m_level = level; }
        std::string getFormatter() const { return m_formatter; }
        void setLogFormatter(const std::string& formatter) { m_formatter = formatter; }
        const std::vector<LogAppender::ptr>& getAppenders() const { return m_appenders; } // otherwise cant not insert! // this func can not insert
        void pushAppender(LogAppender::ptr p) { m_appenders.push_back(p); }

    private:
        std::string         m_log_name;
        LogLevel::Level     m_level;
        std::string         m_formatter;
        std::vector<LogAppender::ptr>   m_appenders;
    };
}

#endif

/*
logger
  |
  +--- formatter: parse log4j conf then collect every items
  |
  +--- appender:  How to use?

How to use?
1. alloc event
2. alloc appender to init logger
logger->log(level, event)
*/
