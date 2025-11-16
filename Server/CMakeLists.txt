cmake_minimum_required(VERSION 3.10)

project(Chat LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Find required packages ----
find_package(Protobuf REQUIRED)
find_package(Threads REQUIRED)

# ---- Protobuf generation ----
set(PROTO_FILES chat.proto)
set(PROTO_SRCS ${CMAKE_CURRENT_BINARY_DIR}/chat.pb.cc)
set(PROTO_HDRS ${CMAKE_CURRENT_BINARY_DIR}/chat.pb.h)

add_custom_command(
    OUTPUT ${PROTO_SRCS} ${PROTO_HDRS}
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --proto_path=${CMAKE_CURRENT_SOURCE_DIR}
         --cpp_out=${CMAKE_CURRENT_BINARY_DIR}
         ${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_FILES}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_FILES}
)

# ---- Include directories ----
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${Protobuf_INCLUDE_DIRS}
)

# ---- Build executable ----
add_executable(chat
    main.cpp
    server.cpp
    database.cpp
    logger.cpp
    threadpool.cpp
    sqlite3.c
    ${PROTO_SRCS}
)

# ---- Link libraries ----
target_link_libraries(chat
    PRIVATE
        ${Protobuf_LIBRARIES}
        Threads::Threads
        dl
)
