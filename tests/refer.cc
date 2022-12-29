#include<iostream>
#include<memory>
#include <unordered_map>
#include<functional>
#include<list>
#include<unistd.h>

class A {
  public:
    using ptr = std::shared_ptr<A>;
    A() :m_ptr(new int(0)) {
      std::cout<<"construct"<<std::endl;
    }

    A(const A& a) :m_ptr(new int(*a.m_ptr)) {
      std::cout<<"cp construct"<<std::endl;
    }

    A& operator=(const A& a) {
        std::cout<<"asign construct"<<std::endl;
        m_ptr = new int(*a.m_ptr);
        return *this;
    }

    A(A&& a) :m_ptr(a.m_ptr) { //为什么move构造 只是一个浅拷贝? 因为他是右值 因为它不需要深拷贝 只需要转移控制权限就可以了
      std::cout<<"move construct"<<std::endl;
      a.m_ptr = nullptr;
    }

    A& operator=(A &&a) {
      std::cout<<"move asign construct"<<std::endl;
        m_ptr = a.m_ptr;
        a.m_ptr = nullptr;
        return *this;
    }

    ~A() {
      std::cout<<"destruct"<<std::endl;
      delete m_ptr;
    }
  //private:
  public:
    int* m_ptr;
};

A Get(bool flag) {
  A a;
  A b;
  return flag ? a : b;
}

void test_A_para(A &&a)
{
    std::cout << "in func a.m_ptr: " << a.m_ptr << std::endl;
}

void test_A_para_move(A &&a)
{
    A b(std::forward<A>(a));
    std::cout << "in func a.m_ptr: " << a.m_ptr << std::endl;
    std::cout << "in func b.m_ptr: " << b.m_ptr << std::endl;
}

template <typename T>
void test_A_para1(T &&t)
{
    std::cout << "in func t.m_ptr: " << t.m_ptr << std::endl;
}

void test_A()
{
#if 0
    A a;
    std::cout << "a.m_ptr: " << a.m_ptr << std::endl;
    A b(std::move(a)); // 1. std::move to rvalue // 2. call A::move construct
    std::cout << "a.m_ptr: " << a.m_ptr << std::endl;
    std::cout << "b.m_ptr: " << b.m_ptr << std::endl;
#else
    A c;
    std::cout << "c.m_ptr: " << c.m_ptr << std::endl;
    //test_A_para(std::move(c)); // 1. std::move to rvalue ONLY
    //test_A_para_move(std::move(c)); // 1. std::move to rvalue // 2. call move in test_A_para_move // 虽然很丑 但是只能用这种方式进行"断舍离"
    std::cout << "c.m_ptr: " << c.m_ptr << std::endl;
#endif
}

class TcpSer {
public:
    using ptr = std::shared_ptr<TcpSer>;
    TcpSer(int x) { m_a = x; }
    ~TcpSer() { std::cout << "~TcpSer" << std::endl; }
private:
    int m_a = 0;
};

void refer_test()
{
    TcpSer::ptr c = std::make_shared<TcpSer>(1);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 1

    //TcpSer::ptr m = std::move(c);
    TcpSer::ptr m = std::forward<TcpSer::ptr>(c); // same as move
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
    std::cout<<"m.use_count(): " << m.use_count() << std::endl; // 1
}

void func_obj_bind()
{
    TcpSer::ptr c = std::make_shared<TcpSer>(1);
    //A::ptr c = std::make_shared<A>();

#if 0
    auto fun_obj = [c]() {
        std::cout << "fun_obj..." << std::endl;
    };
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 2
    fun_obj();
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 2
#else
    auto fun_obj = [&c]() {
        TcpSer::ptr t;
        t.swap(c);
        std::cout << "fun_obj..." << std::endl;
    };
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 1
    fun_obj();                                                  // ~TcpSer
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
#endif
}

void func_obj_bind_move_forward()
{
    TcpSer::ptr c = std::make_shared<TcpSer>(1);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 1

    //auto fun_obj = [c=std::forward<TcpSer::ptr>(c)]() {
    auto fun_obj = [c=std::move(c)]() { // same as forward
        std::cout << "fun_obj...c.use_count(): " << c.use_count() << std::endl;
    };

    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
    std::cout<< "-------------" << std::endl;
    fun_obj(); // 将fun_obj视为一个变量 // 1
    std::cout<< "-------------" << std::endl;
    fun_obj(); // 1
    std::cout<< "-------------" << std::endl;
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
    // ~TcpSer
}

void move_test()
{
    A::ptr c = std::make_shared<A>();
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 1
#if 1
    A::ptr m = std::move(c);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
#else
    A::ptr f = std::forward<A::ptr>(c);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
#endif
}

void forward_test()
{
    TcpSer::ptr c = std::make_shared<TcpSer>(1);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 1

    TcpSer::ptr f = std::forward<TcpSer::ptr>(c);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl; // 0
}

static void para_deal(TcpSer::ptr c)
{
    std::cout<<"in func, c.use_count(): " << c.use_count() << std::endl; // 2
}

static void para_deal_refer(TcpSer::ptr &c)
{
    std::cout<<"in func, c.use_count(): " << c.use_count() << std::endl; // 1
}

static void para_deal_swap(TcpSer::ptr &c)
{
    TcpSer::ptr t;
    t.swap(c);
    std::cout<<"in func, t.use_count(): " << t.use_count() << std::endl; // there is 1 and upper is 0
                                                                         // ~TcpSer
}

void para_deal_move(TcpSer::ptr &&c)
{
    std::cout<<"in func, c.use_count(): " << c.use_count() << std::endl;
}

template<typename T>
static void para_deal_type(T &&c)
{
    //std::cout<<"in func, c.use_count(): " << c.use_count() << std::endl;
    std::cout<<"in func, c.use_count(): " << std::forward<T>(c).use_count() << std::endl;
}

void func_para_test()
{
    TcpSer::ptr c = std::make_shared<TcpSer>(1);
    std::cout<<"c.use_count(): " << c.use_count() << std::endl;
    //para_deal(c);         // very safe
    //para_deal_refer(c);   // not thread-safe
    //para_deal_swap(c);    // swap: upper is 0
    para_deal_move(std::move(c));
    //para_deal_move(std::move(c));
    //para_deal_move(std::forward<TcpSer::ptr>(c));

    //para_deal_type(c); // 1 (lvalue refer)
    //para_deal_type(std::move(c));
    //para_deal_type(std::forward<TcpSer::ptr>(c));
    //para_deal_type(c = std::forward<TcpSer::ptr>(c));

    
    std::cout<<"c.use_count(): " << c.use_count() << std::endl;
}

int main()
{
    //refer_test();
    //func_obj_bind();
    //func_obj_bind_move_forward();
    test_A();
    //func_para_test();
    return 0;
}
