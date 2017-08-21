project(Appster)
cmake_minimum_required(VERSION 2.8)

##
# Files
##

set(SRC_LIST
    src/appster.c
    src/channel.c
    src/evbuffer.c
    src/format.c
    src/hashmap.c
    src/http_parser.c
    src/log.c
    src/redis.c
    src/schema.c
    src/vector.c
)

add_library(${PROJECT_NAME} ${SRC_LIST})

add_executable(example_body src/examples/body.c)
add_executable(example_redis src/examples/redis.c)

target_link_libraries(example_body ${PROJECT_NAME})
target_link_libraries(example_redis ${PROJECT_NAME})

##
# Dependencies
##

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

find_package(Hiredis)
find_package(LibUV REQUIRED)

include_directories(
    ${HIREDIS_INCLUDE_DIR}
    ${LIBUV_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    -ldill
    ${HIREDIS_LIBRARIES}
    ${LIBUV_LIBRARIES}
)

if(HIREDIS_FOUND)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${HIREDIS_DEFINITIONS}")
elseif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DDISABLE_REDIS")
endif()

##
# Compiler & linker flags
##

set(CMAKE_C_FLAGS "-Wall -Wno-sign-compare")

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-unused-function")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -static-libasan")
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
endif()
