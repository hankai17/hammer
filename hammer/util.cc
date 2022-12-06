//
// Created by root on 12/6/22.
//

#include "util.hh"

namespace hammer {
    pid_t GetThreadId() {
        return syscall(SYS_gettid);
    }

}
