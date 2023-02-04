cmake_minimum_required(VERSION 3.24.2)

project(chatserver)

find_package(cryptopp REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp)

target_link_libraries(server PRIVATE cryptopp::cryptopp)
target_link_libraries(client PRIVATE cryptopp::cryptopp)
