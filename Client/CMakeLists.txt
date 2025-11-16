cmake_minimum_required(VERSION 3.10.0)
project(chatClient VERSION 0.1.0 LANGUAGES C CXX)

# Find required packages
find_package(Protobuf REQUIRED)

# Generate protobuf files
set(PROTO_FILES chat.proto)
set(PROTO_SRCS chat.pb.cc)
set(PROTO_HDRS chat.pb.h)

add_custom_command(
    OUTPUT ${PROTO_SRCS} ${PROTO_HDRS}
    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
    ARGS --proto_path=${CMAKE_CURRENT_SOURCE_DIR} --cpp_out=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_FILES}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_FILES}
)

# Include generated protobuf directory
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Create executable
add_executable(chatClient main.cpp client.cpp ${PROTO_SRCS})                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            

# Link libraries
target_link_libraries(chatClient ${Protobuf_LIBRARIES} pthread)
