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

// Server class specification
// Example:
//      Certificate cert(subjectName);
//      CryptoPP::RSA::PrivateKey privateKey = cert.createKeys(2048);
//      cert.sign(CAKey);
class Server {
    public:
        CryptoPP::RSA::PublicKey publicKey;
        struct sockaddr_in serverAddress;
        unsigned int keySize = 2048;
        int nBacklog = 3;
        std::string name = "Server";

        int start(char *serverIP, u_short port);
        int acceptClient(void);
        int readClient(char *buffer);
        int sendClient(const char *msg);

    private:
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::InvertibleRSAFunction params;
        WSADATA wsaData;
        SOCKET serverSocket = INVALID_SOCKET;
        SOCKET clientSocket = INVALID_SOCKET;
        int addrlen = sizeof(serverAddress);

        int createKeys();
};
