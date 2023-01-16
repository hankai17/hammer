cmake_minimum_required(VERSION 3.2)
PROJECT(hammer)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_FLAGS "$ENV{CXXFLAGS} -rdynamic -O0 -ggdb -g -std=c++17 -Wall -Wno-deprecated -Werror -Wno-unused-function -Wno-builtin-macro-redefined")
#set(CMAKE_CXX_FLAGS "$ENV{CXXFLAGS} -rdynamic -O3 -std=c++17 -Wall -Wno-deprecated -Werror -Wno-unused-function -Wno-builtin-macro-redefined")
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

set(ENABLE_OPENSSL true)

include_directories("./" "./tests")

find_library(THREAD pthread /usr/lib64/)
#find_library(GTEST gtest /usr/local/lib64/)

set(LIBS ${PROJECT_NAME}
        pthread
        dl
        jemalloc
        )

set(LIB_SRC
        hammer/nocopy.hh
        hammer/singleton.hh
        hammer/util.cc
        hammer/log.cc
        hammer/event_poller.cc
        hammer/mbuffer.cc
        hammer/uv_errno.cc
        hammer/socket_ops.cc
        hammer/socket.cc
        hammer/tcp_server.cc)

find_package(OpenSSL QUIET)
if(OPENSSL_FOUND AND ENABLE_OPENSSL)
    message(STATUS "找到openssl库:\"${OPENSSL_INCLUDE_DIR}\",ENABLE_OPENSSL宏已打开")
    include_directories(${OPENSSL_INCLUDE_DIR})
    add_definitions(-DENABLE_OPENSSL)
    list(APPEND LIBS ${OPENSSL_LIBRARIES})
endif()

add_library(${PROJECT_NAME} SHARED ${LIB_SRC})

function(hammer_add_executable targetname srcs depends libs)
    add_executable(${targetname} ${srcs})
    add_dependencies(${targetname} ${depends})
    #force_redefine_file_macro_for_source(${targetname})
    target_link_libraries(${targetname} ${libs})
endfunction()

hammer_add_executable(logger_test tests/log_test.cc ${PROJECT_NAME} "${LIBS}")
hammer_add_executable(task_test tests/task_test.cc ${PROJECT_NAME} "${LIBS}")
hammer_add_executable(event_poller tests/event_poller.cc ${PROJECT_NAME} "${LIBS}")
hammer_add_executable(client tests/client.cc ${PROJECT_NAME} "${LIBS}")
