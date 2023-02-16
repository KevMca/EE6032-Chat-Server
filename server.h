// Server header file for communicating with clients
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

#include "protocol.h"

// Server class specification
// Example:
//     Server server;
//     int err = server.start(serverIP, port);
//     if (err != 0) { return 1; }
//     err = server.acceptClient();
//     if (err != 0) { return 1; }
class Server {
    public:
        struct sockaddr_in serverAddress;
        int nBacklog = 3;
        CryptoPP::RSA::PrivateKey privateKey;
        Certificate cert;
        Certificate clientCert;

        Server(void);

        // Constructor for server if private and public keys are known
        // Inputs -> privateName: location of the private key file for the server
        //           publicName: location of the public key file for the server
        Server(const char *privateName, const char *publicName);

        // Starts the server socket and attaches to port and address
        // Inputs -> serverIP: the IP address of the server
        //           port: the port of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int start(char *serverIP, u_short port);

        // Listens on the specified port and connects to the first client that tries to connect
        // Returns -> 0 if no errors, 1 if there was an error
        int listenClient(void);

        // Exchanges certificates with a client and authenticates them
        // Inputs -> CACert: the certificate of the certificate authority
        // Returns -> 0 if no errors, 1 if there was an error
        int connectClient(Certificate CACert);

        // Reads any messages from the attached client
        // Inputs -> buffer: the buffer to read into
        // Returns -> the number of bytes read
        int readClient(char *buffer);

        // Sends a message to the attached client
        // Inputs -> msg: the message to send
        // Returns -> the number of bytes sent
        int sendClient(const char *msg);

    private:
        WSADATA wsaData;
        SOCKET serverSocket = INVALID_SOCKET;
        SOCKET clientSocket = INVALID_SOCKET;
        char buffer[DEFAULT_BUFLEN] = { 0 };
        int addrlen = sizeof(serverAddress);
};
