project(AppsterC)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(src/ SRC_LIST)
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

# include directories for evhtp because it's borked
include_directories(/usr/local/include/evhtp/)
