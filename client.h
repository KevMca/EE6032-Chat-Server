// Client header file for communicating with server and other clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

// Include crypto libraries
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

// Include socket libraries
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// Client class specification
// Example:
//     Client alice;
//     int err = alice.start();
//     if (err != 0) { return 1; }
//     err = server.connectServer(serverIP, port);
//     if (err != 0) { return 1; }
class Client {
    public:
        struct sockaddr_in serverAddress;

        // Starts the client socket
        // Returns -> 0 if no errors, 1 if there was an error
        int start(void);

        // Connects to a server with a specific IP address and port
        // Inputs -> serverIP: the IP address of the server
        //           port: the port number of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int connectServer(char *serverIP, u_short port);

        // Reads any messages from the attached server
        // Inputs -> buffer: the buffer to read into
        // Returns -> the number of bytes read
        int readServer(char *buffer);

        // Sends a message to the attached server
        // Inputs -> msg: the message to send
        // Returns -> the number of bytes sent
        int sendServer(const char *msg);

    private:
        WSADATA wsaData;
        SOCKET serverSocket = INVALID_SOCKET; 
        int addrlen = sizeof(serverAddress);

        // Connects to a server with a specific IP address and port
        // Inputs -> serverIP: the IP address of the server
        //           port: the port number of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int setupServerSocket(char *serverIP, u_short port);
};