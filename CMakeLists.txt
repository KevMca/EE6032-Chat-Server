cmake_minimum_required(VERSION 3.24.2)

project(ChatServer)

add_executable(server socket_server_test.cpp)
add_executable(client socket_client_test.cpp)
