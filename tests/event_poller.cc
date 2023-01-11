//
// Created by root on 12/6/22.
//

#include "hammer/log.hh"
#include "hammer/util.hh"
#include "hammer/event_poller.hh"
#include "hammer/tcp_server.hh"

#include <memory>

static hammer::Logger::ptr g_logger = HAMMER_LOG_NAME("root");

hammer::EventPoller::ptr g_poller = nullptr;

uint64_t timer_cb()
{
    HAMMER_LOG_DEBUG(g_logger) << "timer cb";
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
            HAMMER_LOG_DEBUG(g_logger) << i << " normal cb";
        });
    }
    return 0;
}

int tcp_server_test()
{
    auto poller = hammer::Singleton<hammer::EventPollerPool>::instance().getPoller();
    hammer::TcpServer::ptr server = std::make_shared<hammer::TcpServer>(poller);
    server->start_internal(9527, "0.0.0.0");
    while(1) { sleep(1); }
    return 0;
}

int tcp_server_api()
{
    auto poller = hammer::Singleton<hammer::EventPollerPool>::instance().getPoller();
    hammer::TcpServer::ptr server = std::make_shared<hammer::TcpServer>(poller);
    std::weak_ptr<hammer::TcpServer> weak_self = server;

    server->setOnReadCB([](const hammer::MBuffer::ptr &buf, struct sockaddr *addr, int addr_len) {
        if (buf->readAvailable()) {
            buf->clear();
        }
        //auto strong_sock = shared_from_this();

        /*
        std::string resp = "HTTP/1.1 200 OK\r\n\r\n";
        auto strong_sock = weak_sock.lock();
        if (!strong_sock) {
            return;
        }
        this->send(resp);
        */
    });

    server->setOnWrittenCB([weak_self]()->bool {
        auto strong_self = weak_self.lock();
        if (!strong_self) {
            return false;
        }
        //strong_self->getConnections().erase(this);
        return true;
    });

    server->setOnErrCB([weak_self](const hammer::SocketException &e) {
        hammer::OnceToken token(nullptr, [&]() {
            auto strong_self = weak_self.lock();
            if (!strong_self) {
                return;
            }
            //strong_self->getConnections().erase(sock_ptr);
        });
    });

    // 如果暴力点 这个回调参数中 应该加上socket 就行muduo里一样
    // 缺点: 直接在server里注册业务回调 太过暴力且不优雅 违背设计模式6大原则2)单一原则
    // 应该 设计成继承或是模板

    // 直接设计一个中间层session里面包装有socket 然后tcp_server对外暴露的业务回调中(即业务回调点:onRead/onErr ) 调用session
    server->start_internal(9527, "0.0.0.0");
    while(1) { sleep(1); }
    return 0;
}

class EchoSession : public hammer::Session {
public:
    EchoSession(const hammer::TcpServer::ptr &server, const hammer::Socket::ptr &sock) 
        : hammer::Session(server, sock) {}
    ~EchoSession() {}
    
    virtual void onRecv(const hammer::MBuffer::ptr &buf) {
        //buf->clear();
        auto resp = std::make_shared<hammer::MBuffer>("HTTP/1.1 200 OK\r\n\r\n");
        send(resp);
        //safeShutdown(); 
        //shutdown(hammer::SocketException(hammer::ERRCode::SHUTDOWN, "shutdown"));
    }
    virtual void onWritten() {
        //safeShutdown();
        shutdown(hammer::SocketException(hammer::ERRCode::SHUTDOWN, "shutdown"));
    }
    virtual void onError(const hammer::SocketException &e) {
        //HAMMER_LOG_WARN(g_logger) << "onError cb";
    }
    virtual void onManager() {
        HAMMER_LOG_WARN(g_logger) << "onManager cb";
    }
private:
};

int test_server()
{
    auto poller = hammer::Singleton<hammer::EventPollerPool>::instance().getPoller();
    hammer::TcpServer::ptr server = std::make_shared<hammer::TcpServer>(poller);
    server->start<EchoSession>(9527, "0.0.0.0");
    while(1) { sleep(1); }
    return 0;
}

int main()
{
    //tcp_server_test();
    //tcp_server_api();
    test_server();
    while(1) { sleep(1); }
    return 0;
}
