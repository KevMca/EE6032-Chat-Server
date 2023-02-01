// Server side C/C++ program to demonstrate Socket programming
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
    
    char* hello = "Hello from server";      // Message to send to client in response
    char opt = 1;                           // Controls SO_REUSEADDR option
    int nBacklog = 3;                       // Maximum number of pending connections allowed
    char buffer[DEFAULT_BUFLEN] = { 0 };    // Message receive buffer
    WSADATA wsaData;
    SOCKET serverSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddress;
    int addrlen = sizeof(serverAddress);
    int err, valread;
 
    printf("SERVER SIDE\n-----------\n");

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
 
    // Forcefully (SO_REUSEADDR) attaching socket to the port
    err = setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (err != 0) {
        printf("Setting socket option (setsockopt) failed with error: %d\n", err);
        return 1;
    }
 
    // Forcefully attaching socket to the port and address
    serverAddress.sin_family = AF_INET;           // IPv4 addresses used
    serverAddress.sin_addr.s_addr = INADDR_ANY;   // Binds to all devices on the machine
    serverAddress.sin_port = htons(PORT);         // htons converts host bye order to network bye order
    //serverAddress.sin_addr.s_addr = inet_addr("127.0.0.1") // alternative address setting
    err = bind(serverSocket, (struct sockaddr*)&serverAddress, addrlen);
    if (err != 0) {
        printf("Bind failed with error: %d\n", err);
        return 1;
    }

    // Put in passive listening mode
    err = listen(serverSocket, nBacklog);
    if (err != 0) {
        printf("Listen failed with error: %d\n", err);
        return 1;
    }
    printf("Listening.\n");

    // Accept the first connection on the queue and setup socket connection
    clientSocket = accept(serverSocket, (struct sockaddr*)&serverAddress, (int *)&addrlen);
    if (clientSocket == INVALID_SOCKET) {
        printf("Client socket setup failed with error: %d\n", clientSocket);
        return 1;
    }
    printf("Connection made.\n");

    // Read in buffer
    valread = recv(clientSocket, buffer, DEFAULT_BUFLEN, 0);
    printf("From client: %s\n", buffer);

    // Send return message
    send(clientSocket, hello, strlen(hello), 0);
    printf("From me: %s\n", hello);
 
    // Closing the connected socket
    closesocket(clientSocket);
    // Closing the listening socket
    shutdown(serverSocket, SD_BOTH);
    return 0;
}