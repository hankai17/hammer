//
// Created by root on 12/6/22.
//

#ifndef HAMMER_SOCKET_HH
#define HAMMER_SOCKET_HH

#include <unistd.h>
#include <memory>

#include "nocopy.hh"
#include "event_poller.hh"
#include "mbuffer.hh"

namespace hammer {
    enum ERRCode : uint64_t {
        SUCCESS = 0,
        EEOF,
        TIMEOUT,
        REFUSE,
        DNS,
        SHUTDOWN,
        OTHER = 0xFF,
    };

    class SocketException : public std::exception {
    public:
        SocketException(ERRCode code = ERRCode::SUCCESS, const std::string &msg = "", int custom_code = 0)
            : m_code(code), m_msg(msg), m_custom_code(custom_code) {
        }
        void reset(ERRCode code, const std::string &msg, int custom_code = 0) {
            m_code = code;
            m_msg = msg;
            m_custom_code = code;
        }
        const char *what() const noexcept override { return m_msg.c_str(); }
        ERRCode getERRCode() const { return m_code; }
        int getCustomCode() const { return m_custom_code; }
        operator bool() const { return m_code != ERRCode::SUCCESS; }
    private:
        ERRCode     m_code = ERRCode::SUCCESS;
        std::string m_msg = "";
        int         m_custom_code = 0;
    };

    template<typename Mtx = std::recursive_mutex>
    class MutexWrapper {
    public:
        using ptr = std::shared_ptr<MutexWrapper>;
        MutexWrapper(bool enable) : m_enable(enable) {}
        ~MutexWrapper() = default;
        inline void lock() {
            if (m_enable) {
                m_mutex.lock();
            }
        }
        inline void unlock() {
            if (m_enable) {
                m_mutex.unlock();
            }
        }
    private:
        bool    m_enable;
        Mtx     m_mutex; 
    };

    class SocketFD : public Nocopyable {
    public:
        using ptr = std::shared_ptr<SocketFD>;
        enum SocketType {
            INVALID = -1,
            TCP = 0,
            UDP = 1,
        }; 
        SocketFD(int fd, SocketType type, const EventPoller::ptr &poller) :
                m_fd(fd), m_type(type), m_poller(poller) {}
        ~SocketFD() {
            m_poller->delEvent(m_fd, [](int) {});
        }
        int getFD() const { return m_fd; }
        SocketType getType() const { return m_type; }
    private:
        int                 m_fd;
        SocketType          m_type;
        EventPoller::ptr    m_poller;
    };

    class Socket : public std::enable_shared_from_this<Socket>, public Nocopyable {
    public:
        using ptr = std::shared_ptr<Socket>;
        using ConnCB = std::function<void(int)>;
        using onErrCB = std::function<void(const std::string &)>;
        using onReadCB = std::function<void(const MBuffer::ptr &, struct sockaddr *, int addr_len)>;
        using onAcceptCB = std::function<void(Socket::ptr &, std::shared_ptr<void> &)>;
        using onFlushCB = std::function<bool()>;
        using onCreateSocketCB = std::function<ptr(const EventPoller::ptr &)>;

        Socket(const EventPoller::ptr poller = nullptr, bool enable_mutex = true);
        void closeSocket();
        ~Socket();
        static Socket::ptr createSocket(const EventPoller::ptr &poller, bool enable_mutex = true);
        SocketFD::ptr setSocketFD(int fd);

        bool emitErr(const SocketException &err) noexcept;
        void stopWriteAbleEvent(const SocketFD::ptr &sock);

        ssize_t onRead(const SocketFD::ptr &sock, bool is_udp) noexcept;
        bool writeData(const SocketFD::ptr &sock, bool poller_thead);
        void onWriteAble(const SocketFD::ptr &sock);

        bool attachEvent(const SocketFD::ptr &sock);

        int onAccept(const SocketFD::ptr &sock, int event);


    private:
        EventPoller::ptr    m_poller = nullptr;
        SocketFD::ptr       m_fd;
        Timer::ptr          m_conn_timer = nullptr;
        ConnCB              m_conn_cb = nullptr;
        MBuffer::ptr        m_read_buffer = nullptr;
        mutable MutexWrapper<std::recursive_mutex>  m_socketFD_mutex;

        onErrCB             m_on_err_cb = nullptr;
        onCreateSocketCB    m_on_before_accept_cb = nullptr; // consutruct by self costom
        onAcceptCB          m_on_accept_cb = nullptr;
        onReadCB            m_on_read_cb = nullptr;
        onFlushCB           m_on_flush_cb = nullptr;
        MutexWrapper<std::recursive_mutex>  m_event_cb_mutex;

        bool                m_enable_recv = true;
        bool                m_write_triggered = true;

        MBuffer::ptr        m_write_buffer_waiting = nullptr;
        MutexWrapper<std::recursive_mutex>  m_write_buffer_waiting_mutex;
        MBuffer::ptr        m_write_buffer_sending = nullptr;
        MutexWrapper<std::recursive_mutex>  m_write_buffer_sending_mutex;
    };
    
}

#endif //HAMMER_SOCKET_HH
