project(Appster)
cmake_minimum_required(VERSION 2.8)

##
# Files
##

set(SRC_LIST
    src/appster.c
    src/channel.c
    src/format.c
    src/log.c
    src/redis.c
    src/schema.c
)

add_library(${PROJECT_NAME} ${SRC_LIST})

##
# Dependencies
##

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

add_subdirectory(deps)
include_directories(SYSTEM deps)
target_link_libraries(${PROJECT_NAME}
    deps
)

find_package(Hiredis)
find_package(libdill REQUIRED)
find_package(LibUV REQUIRED)

include_directories(
    ${HIREDIS_INCLUDE_DIR}
    ${LIBDILL_INCLUDE_DIRS}
    ${LIBUV_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME}
    ${HIREDIS_LIBRARIES}
    ${LIBDILL_LIBRARIES}
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

##
# Examples
##

add_executable(example_body src/examples/body.c)
add_executable(example_redis src/examples/redis.c)

target_link_libraries(example_body ${PROJECT_NAME} deps)
target_link_libraries(example_redis ${PROJECT_NAME} deps)
