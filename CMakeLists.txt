cmake_minimum_required(VERSION 3.24.2)

project(chatserver)

find_package(cryptopp REQUIRED)

set(SRCS src/cert.cpp src/encryption.cpp src/protocol.cpp src/logging.cpp)

add_executable(server src/server.cpp ${SRCS})
add_executable(client src/client.cpp ${SRCS})
add_executable(ca_cert utils/ca_cert.cpp ${SRCS})
add_executable(client_cert utils/client_cert.cpp ${SRCS})

target_link_libraries(server PRIVATE cryptopp::cryptopp)
target_link_libraries(client PRIVATE cryptopp::cryptopp)
target_link_libraries(ca_cert PRIVATE cryptopp::cryptopp)
target_link_libraries(client_cert PRIVATE cryptopp::cryptopp)
