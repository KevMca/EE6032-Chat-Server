// Client side C/C++ program to demonstrate Socket programming
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// Server side C/C++ program to demonstrate Socket

// Include socket libraries
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Other includes
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_BUFLEN 1024
#define PORT 8080
 
int main(int argc, char const* argv[])
{   
    char* serverIP = "127.0.0.1";           // Server IP address
    char* hello = "Hello from client";      // Message to send to server
    char buffer[DEFAULT_BUFLEN] = { 0 };    // Message receive buffer
    WSADATA wsaData;
    SOCKET serverSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddress;
    int addrlen = sizeof(serverAddress);
    int err, valread;

    printf("CLIENT SIDE\n-----------\n");

    // Initialize Winsock
    err = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (err != 0) {
        printf("WSAStartup failed with error: %d\n", err);
        return 1;
    }

    // Creating IPv4 socket object
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        printf("Server socket setup failed with error: %d\n", serverSocket);
        return 1;
    }
 
    // Setup server address type and port
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
 
    // Convert address from text to binary form
    err = inet_pton(AF_INET, serverIP, &serverAddress.sin_addr);
    if (err != 1) {
        printf("Address conversion error: %d\n", err);
        return 1;
    }
 
    // Attempt a connection to the server
    err = connect(serverSocket, (struct sockaddr*)&serverAddress, addrlen);
    if (err != 0) {
        printf("Connection to server failed: %d\n", err);
        return 1;
    }
    printf("Connection made.\n");

    // Send message to server
    send(serverSocket, hello, strlen(hello), 0);
    printf("From me: %s\n", hello);

    // Listen to response from server
    valread = recv(serverSocket, buffer, DEFAULT_BUFLEN, 0);
    printf("From server: %s\n", buffer);
 
    // closing the connected socket
    closesocket(serverSocket);
    return 0;
}