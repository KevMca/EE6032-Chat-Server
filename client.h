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

#include <iomanip>
#include <conio.h>
#include "cert.h"
#include "protocol.h"

// Client session class for other clients connected to the server
// Example:
//     ClientSession(cert, socket);
class ClientSession {
    public:
        Certificate cert;
        std::string partialKey;

        ClientSession();
        ClientSession(Certificate cert);
};

// Client class specification
// Example:
//     Client alice;
//     int err = alice.start();
//     if (err != 0) { return 1; }
//     err = server.connectServer(serverIP, port);
//     if (err != 0) { return 1; }
class Client {
    public:
        SOCKET serverSocket = INVALID_SOCKET;
        struct sockaddr_in serverAddress;
        CryptoPP::RSA::PrivateKey privateKey;
        Certificate cert;
        Certificate serverCert;
        std::vector<ClientSession> clients;
        std::string partialKey;

        explicit Client(void);

        // Constructor for client if private and public keys are known
        // Inputs -> privateName: location of the private key file for the client
        //           publicName: location of the public key file for the client
        explicit Client(const char *privateName, const char *publicName);

        // Starts the client socket
        // Returns -> 0 if no errors, 1 if there was an error
        int start(void);

        // Connects to a server with a specific IP address and port
        // Inputs -> serverIP: the IP address of the server
        //           port: the port number of the server
        //           CACert: the certificate of the certificate authority
        // Returns -> 0 if no errors, 1 if there was an error
        int connectServer(char *serverIP, u_short port, Certificate CACert);

        int sendPartialKey(void);

        // Adds a client certificate to the list of other clients, if it doesn't already exist
        // Inputs -> clientCert: the certificate of a different client connected to the server
        // Returns -> true if certificate already, false if certificate already existed
        bool updateClients(Certificate &clientCert);

        // Prints the current table of other clients
        void printClients(void);

    private:
        WSADATA wsaData;
        int addrlen = sizeof(serverAddress);

        // Connects to a server with a specific IP address and port
        // Inputs -> serverIP: the IP address of the server
        //           port: the port number of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int setupServerSocket(char *serverIP, u_short port);
};