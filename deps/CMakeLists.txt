project(deps)

set(SRC_LIST
    evbuffer.c
    hashmap.c
    http_parser.c
    vector.c
)

add_library(deps ${SRC_LIST})
