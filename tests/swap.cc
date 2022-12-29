#include<iostream>
#include<memory>
#include <unordered_map>
#include<functional>
#include<list>
#include<unistd.h>

int test(std::shared_ptr<int>* addr) {
    std::shared_ptr<int> t;
    t.swap(*addr);
    std::cout<<"test: a: " << *t << std::endl;
    return 0;
}

int main1() {
    std::shared_ptr<int> a(new int(9));
    std::shared_ptr<int>* pa = &a;
    std::cout<<"in main before test: a: " << *a << std::endl;
    test(pa);
    if (a == nullptr) {
        std::cout<<"is nullptr" << std::endl;
    } else {
        std::cout<<"in main after test: a: " << *a << std::endl;
    }
    return 0;
}

//////////////////////////////////////

int test1(std::shared_ptr<int> addr) {
    std::cout<<"test1: addr.use_count(): " << addr.use_count() << std::endl;
    std::shared_ptr<int> t;
    t.swap(addr);
    //t = addr;
    std::cout<<"test1: a: " << *t << ",  t.use_count(): "
             << t.use_count() << "  addr.use_count(): " << addr.use_count() <<std::endl;
    return 0;
}

struct a {
    typedef std::shared_ptr<a> ptr;
    a() {std::cout << "construct a" << std::endl;};
    ~a() {std::cout << "free a" << std::endl;}
    int va;
};

struct c {
    typedef std::shared_ptr<c> ptr;
    int vc;
    a::ptr a_ptr;
};

int main2() {
    std::shared_ptr<int> a(new int(9));
    test1(a);
    if (a == nullptr) {
        std::cout<<"is nullptr" << std::endl;
    } else {
        std::cout<<"in main after test: a: " << *a << std::endl;
        std::cout << "a.use_count(): " << a.use_count() <<std::endl;
    }
    return 0;
}

void test3() {
    std::cout << "test3..." << std::endl;
    return;
}

int main3()
{
    struct a a1;
    std::shared_ptr<void> completed(nullptr, [](void *) {
        std::cout << "completed..." << std::endl; // 析构时调用
    });

#if 1
    int t = 100;
    auto fun = [t, completed](void) {   // 延长completed的生命周期 与该funOBJ生命周期一样长?
        std::cout << "complete.use_count: " << completed.use_count() << std::endl;
        test3();
    };
    fun();
#endif
    return 0; 
}

std::list<std::function<void(void)>> g_funcs;
std::function<void(void)> main4()
{
    std::shared_ptr<void> completed(nullptr, [](void *) {
        std::cout << "completed..." << std::endl; // 析构时调用
    });

    std::shared_ptr<void> completed1(nullptr, [](void *) {
        std::cout << "completed1..." << std::endl; // 析构时调用
    });

    int t = 100;
    struct a a1;
    std::function<void(void)> fun = [t, a1, completed1, completed](void) {   // 延长completed的生命周期 与该funOBJ生命周期一样长?
        std::cout << "complete.use_count: " << completed.use_count() << std::endl;
        test3();
    };
    return fun; 
}

void main5()
{
    auto fun = main4();
    g_funcs.emplace_back(std::move(fun));
    g_funcs.front()();
    sleep(2);
}

class TcpSer {
public:
    using ptr = std::shared_ptr<TcpSer>;
    TcpSer(int x) { m_a = x; }
    ~TcpSer() { std::cout << "~TcpSer" << std::endl; }
private:
    int m_a = 0;
};

std::unordered_map<TcpSer *, TcpSer::ptr> g_conns;

void main6()
{
    TcpSer::ptr c = std::make_shared<TcpSer>(1);
    std::cout << "before emplace, count: " << c.use_count() << std::endl;
    auto ret = g_conns.emplace(c.get(), c);
    std::cout << "ret.sec: " << ret.second << std::endl; 
    std::cout << "after emplace, count: " << c.use_count() << std::endl;
    return;
}

std::weak_ptr<int> g_w;

void observe()
{
    std::cout << "g_w.use_count(): " << g_w.use_count() << std::endl;
    if (std::shared_ptr<int> sp = g_w.lock()) {
        std::cout << "*sp: " << *sp << std::endl;
    } else {
        std::cout << "g_w is expired, owner_before: " << g_w.owner_before(g_w) << std::endl;
    }
}

void main7()
{
    {
        auto sp = std::make_shared<int>(42);
        g_w = sp;
        std::cout << "owner_before: " << sp.owner_before(g_w) << std::endl;
        observe();
    }
    observe();
}

int main()
{
    //auto fun = main4();
    return 0;
}
