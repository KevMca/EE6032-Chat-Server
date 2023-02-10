cmake_minimum_required(VERSION 3.24.2)

project(chatserver)

find_package(cryptopp REQUIRED)

add_executable(server server.cpp)
add_executable(client client.cpp)
add_executable(cert_exchange cert_exchange.cpp cert.cpp encryption.cpp)
add_executable(cert_creation cert_creation.cpp cert.cpp encryption.cpp)

target_link_libraries(server PRIVATE cryptopp::cryptopp)
target_link_libraries(client PRIVATE cryptopp::cryptopp)
target_link_libraries(cert_exchange PRIVATE cryptopp::cryptopp)
target_link_libraries(cert_creation PRIVATE cryptopp::cryptopp)
