//
// Created by root on 12/6/22.
//

#ifndef HAMMER_SOCKET_HH
#define HAMMER_SOCKET_HH

#include <unistd.h>
#include <sys/socket.h>
#include <memory>
#include <atomic>

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

    class SocketNO {
    public:
        using ptr = std::shared_ptr<SocketNO>;
        SocketNO(int fd) : m_fd(fd) {}
        ~SocketNO();
        int getFD() const { return m_fd; }
        void shutdown() { ::shutdown(m_fd, SHUT_WR); }
    private:
        int         m_fd;
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
                m_type(type), m_poller(poller) {
            m_fd = std::make_shared<SocketNO>(fd);
        }
        SocketFD(const SocketFD &that, const EventPoller::ptr &poller) {
            m_fd = that.m_fd;
            m_poller = poller;
            if (m_poller == that.m_poller) {
                throw std::invalid_argument("copy a SocketFD with same poller");
            }
        }
        ~SocketFD() {
            m_poller->delEvent(m_fd->getFD(), [](int) {});
        }
        void shutdown() { m_fd->shutdown(); }
        int getFD() const { return m_fd->getFD(); }
        SocketType getType() const { return m_type; }
    private:
        SocketNO::ptr       m_fd;
        SocketType          m_type;
        EventPoller::ptr    m_poller;
    };

    class Socket : public std::enable_shared_from_this<Socket>, public Nocopyable {
    public:
        using ptr = std::shared_ptr<Socket>;
        using onCreateSocketCB = std::function<Socket*(const EventPoller::ptr &)>;
        using onAcceptCB = std::function<void(Socket *)>;
        using onReadCB = std::function<void(const MBuffer::ptr &, struct sockaddr *, int addr_len)>;
        using onWrittenCB = std::function<bool()>;
        using onErrCB = std::function<void(const SocketException &)>;
        using ConnCB = std::function<void(int)>;

        Socket(const EventPoller::ptr poller = nullptr, bool enable_mutex = true);
        void shutdownSocket();
        void closeSocket();
        bool isClosed();
        ~Socket();
        static Socket::ptr createSocket(const EventPoller::ptr &poller, bool enable_mutex = true);
        static Socket* createSocketPtr(const EventPoller::ptr &poller, bool enable_mutex = true);
        SocketFD::ptr setSocketFD(int fd);

        std::string getLocalIP();
        uint16_t getLocalPort();
        std::string getPeerIP();
        uint16_t getPeerPort();
        int getFD() { if (m_fd) return m_fd->getFD();  return -1; }

        bool emitErr(const SocketException &err) noexcept;
        void enableRead(const SocketFD::ptr &sock);     // default enable in attachEvent. Never use xxRead !
        void disableRead(const SocketFD::ptr &sock);    // Because we(upper) always enable read Unless a DONE sig
        void enableWrite(const SocketFD::ptr &sock);
        void disableWrite(const SocketFD::ptr &sock);

        void setReadTriggered(bool triggered) { m_read_triggered = triggered; }
        void setWriteTriggered(bool triggered) { m_write_triggered = triggered; }
        bool isReadTriggered() const { return m_read_triggered; }
        bool isWriteTriggered() const { return m_write_triggered; }

        ssize_t onRead(const SocketFD::ptr &sock, bool is_udp) noexcept;
        void onWritten(const SocketFD::ptr &sock);
        bool writeData(const SocketFD::ptr &sock);
        void onWrite(const SocketFD::ptr &sock);

        bool attachEvent(const SocketFD::ptr &sock);

        bool listen(const SocketFD::ptr &sock);
        bool listen(uint16_t port, const std::string& local_ip, int backlog);
        int onAccept(const SocketFD::ptr &sock, int event);

        void onConnected(const SocketFD::ptr &sock, const onErrCB &cb);
        void connect(const std::string &url, uint16_t port, const onErrCB &err_cb, float timeout = 5 * 1000,
                const std::string &local_ip = "::", uint16_t local_port = 0);
        void connect_l(const std::string &url, uint16_t port, const onErrCB &err_cb, float timeout,
                const std::string &local_ip, uint16_t local_port);
        int flushAll();
        ssize_t send_l(MBuffer::ptr buf);
        ssize_t send(const char *buf, size_t size = 0, struct sockaddr *addr = nullptr, socklen_t addr_len = 0);
        ssize_t send(std::string buf, struct sockaddr *addr = nullptr, socklen_t addr_len = 0);
        ssize_t send(MBuffer::ptr buf, struct sockaddr *addr = nullptr, socklen_t addr_len = 0);

        EventPoller::ptr getPoller() const { return m_poller; }
        MutexWrapper<std::recursive_mutex> &getFdMutex() const { return m_socketFD_mutex; }
        void setSockFD(const SocketFD::ptr &fd) { m_fd = fd; }
        SocketFD::ptr getSockFD() const { return m_fd; }
        const onErrCB &getErrCB() { return m_on_err_cb; }

        void setOnBeforeAcceptCB(onCreateSocketCB cb);
        void setOnAcceptCB(onAcceptCB cb);
        void setOnReadCB(onReadCB cb);
        void setOnWrittenCB(onWrittenCB cb);
        void setOnErrCB(onErrCB cb);

        SocketFD::ptr cloneSocketFD(const Socket &other);
        bool cloneFromListenSocket(const Socket &other);

    private:
        EventPoller::ptr    m_poller = nullptr;
        SocketFD::ptr       m_fd = nullptr;
        Timer::ptr          m_conn_timer = nullptr;
        std::shared_ptr<ConnCB> m_conn_cb = nullptr;
        MBuffer::ptr        m_read_buffer = nullptr;
        mutable MutexWrapper<std::recursive_mutex>  m_socketFD_mutex;

        onCreateSocketCB    m_on_before_accept_cb = nullptr;
        onAcceptCB          m_on_accept_cb = nullptr;
        onReadCB            m_on_read_cb = nullptr;
        onWrittenCB         m_on_written_cb = nullptr;
        onErrCB             m_on_err_cb = nullptr;
        MutexWrapper<std::recursive_mutex>  m_event_cb_mutex;

        bool                m_read_enable = false;
        bool                m_write_enable = false;
        bool                m_read_triggered = false;
        bool                m_write_triggered = true;
        bool                m_is_closed = false;

        MBuffer::ptr        m_write_buffer_waiting = nullptr;
        MutexWrapper<std::recursive_mutex>  m_write_buffer_waiting_mutex;
        MBuffer::ptr        m_write_buffer_sending = nullptr;
        MutexWrapper<std::recursive_mutex>  m_write_buffer_sending_mutex;
    };
}

#endif //HAMMER_SOCKET_HH
