cmake_minimum_required(VERSION 3.24.2)

project(chatserver)

find_package(cryptopp REQUIRED)

add_executable(server socket_server_test.cpp)
add_executable(client socket_client_test.cpp)
add_executable(aes aes.cpp)
add_executable(rsa rsa.cpp)

target_link_libraries(aes PRIVATE cryptopp::cryptopp)
target_link_libraries(rsa PRIVATE cryptopp::cryptopp)
