cmake_minimum_required(VERSION 3.24.2)

project(chatserver)

find_package(cryptopp REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp)
add_executable(ca_cert utils/ca_cert.cpp cert.cpp encryption.cpp)
add_executable(client_cert utils/client_cert.cpp cert.cpp encryption.cpp)

target_link_libraries(server PRIVATE cryptopp::cryptopp)
target_link_libraries(client PRIVATE cryptopp::cryptopp)
target_link_libraries(ca_cert PRIVATE cryptopp::cryptopp)
target_link_libraries(client_cert PRIVATE cryptopp::cryptopp)
