#include "hammer/log.hh"
#include "hammer/util.hh"
#include "hammer/event_poller.hh"
#include "hammer/tcp_server.hh"

#define SERV_IP "0.0.0.0"
#define SERV_PORT 9527
#define CONCURRENCY 10

uint64_t g_cconn = 0;
static hammer::Logger::ptr g_logger = HAMMER_LOG_NAME("root");
const char *req_header = "GET / HTTP/1.1\r\nUser-Agent: curl/7.20.0 (x86_64-target-linux-gnu) libcurl/7.32.0 GnuTLS/2.12.23 zlib/1.2.8\r\nHost: 0.0.0.0\r\nAccept: */*\r\n\r\n";

class EchoSession : public hammer::Session {
public:
    EchoSession(const hammer::TcpServer::ptr &server, const hammer::Socket::ptr &sock) 
        : hammer::Session(server, sock) {}
    ~EchoSession() {}
    
    virtual void onRecv(const hammer::MBuffer::ptr &buf) {
        buf->clear();
        auto resp = std::make_shared<hammer::MBuffer>("HTTP/1.1 200 OK\r\n\r\n");
        send(resp);
    }
    virtual void onWritten() {
        shutdown(hammer::SocketException(hammer::ERRCode::SHUTDOWN, "shutdown"));
    }
    virtual void onError(const hammer::SocketException &e) {
    }
    virtual void onManager() {
        HAMMER_LOG_DEBUG(g_logger) << "onManager cb";
    }
private:
};

void test_client(const hammer::EventPoller::ptr &poller)
{
    auto req = std::make_shared<hammer::MBuffer>(req_header);
    hammer::Socket::ptr sock = hammer::Socket::createSocket(poller); 
    sock->connect("0.0.0.0", 9527, [=](const hammer::SocketException &e) {
        //HAMMER_LOG_DEBUG(g_logger) << "onError cb: " << e.what();
        sock->send(req);
    });
    sock->setOnReadCB([](const hammer::MBuffer::ptr &buf, struct sockaddr *addr, int addr_len) {
        if (buf->readAvailable()) {
            //HAMMER_LOG_DEBUG(g_logger) << buf->readAvailable();
            return;
        }
    });
    sock->setOnWrittenCB([sock]()->bool {
        return true;
    });
    sock->setOnErrCB([sock](const hammer::SocketException &e) {
        g_cconn--;
    });
}

uint64_t client_statics()
{
    if (g_cconn < CONCURRENCY) {
        auto poller = hammer::Singleton<hammer::EventPollerPool>::instance().getPoller();
        test_client(poller);
        g_cconn++;
        //HAMMER_LOG_DEBUG(g_logger) << "g_cconn: " << g_cconn;
    }
    return 1 * 1;
}

void test_tcp_client(const hammer::EventPoller::ptr &poller)
{
    hammer::TcpClient::ptr client = std::make_shared<hammer::TcpClient>(poller);
    client->startConnect("0.0.0.0", 9527);
    while(1) { sleep(1); }
}

class SimpleClient : public hammer::TcpClient {
public:
    using ptr = std::shared_ptr<SimpleClient>;
    SimpleClient() {}
    virtual ~SimpleClient() {}
    
protected:
    virtual void onConnect(const hammer::SocketException &e) override {
        HAMMER_LOG_DEBUG(g_logger) << "onConnect: " << e.what();
        const char *req_header = "GET / HTTP/1.1\r\nUser-Agent: curl/7.20.0 (x86_64-target-linux-gnu) libcurl/7.32.0 GnuTLS/2.12.23 zlib/1.2.8\r\nHost: www.baidu.com\r\nAccept: */*\r\n\r\n";
        auto req = std::make_shared<hammer::MBuffer>(req_header);
        send(req);
    };
    virtual void onRecv(const hammer::MBuffer::ptr &buf) override {
        HAMMER_LOG_DEBUG(g_logger) << "onRecv: " << buf->toString();
        buf->clear();
        shutdown(hammer::SocketException(hammer::ERRCode::SHUTDOWN, "shutdown"));
    }
    virtual void onWritten() override {
        HAMMER_LOG_DEBUG(g_logger) << "onWritten ";
    }
    virtual void onError(const hammer::SocketException &e) override {
        HAMMER_LOG_DEBUG(g_logger) << "onError: " << e.what();
    }
    virtual void onManager() override {
        HAMMER_LOG_DEBUG(g_logger) << "onManager";
    }
private:
};

void test_simple_client()
{
    auto client = std::make_shared<SimpleClient>();
    client->startConnect("0.0.0.0", 9527);
    while(1) { sleep(1); }
}

void test_simple_ssl_client()
{
    auto client = std::make_shared<hammer::TcpClientWithSSL<SimpleClient>>();
    client->startConnect("www.baidu.com", 443);
    while(1) { sleep(1); }
}

void test_ssl_box()
{
    std::string cert = "server.pem";
    //std::string cert = "ssl.p12";
    hammer::Singleton<hammer::SSL_Initor>::instance().loadCertificate((hammer::exeDir() + cert).data());
    hammer::Singleton<hammer::SSL_Initor>::instance().trustCertificate((hammer::exeDir() + cert).data());
    hammer::Singleton<hammer::SSL_Initor>::instance().ignoreInvalidCertificate(false);

    hammer::SSL_Box server(true);
    hammer::SSL_Box client(false);

    server.setOnDecData([&](const hammer::MBuffer::ptr &buffer) {
        HAMMER_LOG_DEBUG(g_logger) << "server recv: " << buffer->toString();
        server.onSend(buffer);
    });
    server.setOnEncData([&](const hammer::MBuffer::ptr &buffer) {
        client.onRecv(buffer);
    });

    client.setOnDecData([&](const hammer::MBuffer::ptr &buffer) {
        HAMMER_LOG_DEBUG(g_logger) << "client recv: " << buffer->toString();
    });
    client.setOnEncData([&](const hammer::MBuffer::ptr &buffer) {
        server.onRecv(buffer);
    });

    HAMMER_LOG_DEBUG(g_logger) << "please input string to test. 'quit' is stop";
    std::string input;
    while (true) {
        std::cin >> input;
        if (input == "quit") {
            break;
        }
        client.onSend(std::make_shared<hammer::MBuffer>(input));
    }
    return;
}

int main()
{
    auto poller = hammer::Singleton<hammer::EventPollerPool>::instance().getPoller();
    hammer::TcpServer::ptr server = std::make_shared<hammer::TcpServer>(poller);
    server->start<EchoSession>(9527, "0.0.0.0");
    //test_client(poller);
    //poller->doTimerTask(1000 * 1,  client_statics);

    //test_tcp_client(poller);
    //test_simple_client();
    //test_ssl_box();
    test_simple_ssl_client();
    while(1) { sleep(1); }
    return 0;
}

// https://github.com/ZLMediaKit/ZLMediaKit/wiki/%E7%94%9F%E6%88%90SSL%E8%87%AA%E7%AD%BE%E5%90%8D%E8%AF%81%E4%B9%A6%E5%B9%B6%E6%B5%8B%E8%AF%95
