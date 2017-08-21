project(Appster)
cmake_minimum_required(VERSION 2.8)

set(SRC_LIST
    src/appster.c
    src/channel.c
    src/evbuffer.c
    src/format.c
    src/hashmap.c
    src/http_parser.c
    src/log.c
    src/redis.c
    src/shema.c
    src/vector.c
    src/main.c
)

add_executable(${PROJECT_NAME} ${SRC_LIST})

target_link_libraries(${PROJECT_NAME}
    -ldill
    -lhiredis
    -luv
)

set(CMAKE_C_FLAGS "-Wall -Wno-sign-compare")

#if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-unused-function")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -static-libasan")
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
#else()
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
#endif()
