#ifndef __NOCOPY_HH__
#define __NOCOPY_HH__

namespace hammer {
    class Nocopyable {
    public:
        Nocopyable() = default;
        ~Nocopyable() = default;
        Nocopyable(const Nocopyable&) = delete;
        Nocopyable&operator=(const Nocopyable& r) = delete;
    };
}

#endif
