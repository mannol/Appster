project(AppsterC)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(src/ SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

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

#if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wno-unused-function")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -static-libasan")
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
#else()
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
#endif()
