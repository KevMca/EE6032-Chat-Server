// Client class for communicating with server and other clients
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

// Include other libraries
#include <iostream>
#include <string>

#define DEFAULT_BUFLEN 1024

// Client class specification
class Client {
    public:
        CryptoPP::RSA::PublicKey publicKey;
        struct sockaddr_in serverAddress;
        unsigned int keySize = 3072;
        std::string name;

        Client(std::string _name);
        int start(void);
        int connectServer(char *serverIP, u_short port);
        int readServer(char *buffer);
        int sendServer(const char *msg);

    private:
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSA::PrivateKey privateKey;
        CryptoPP::InvertibleRSAFunction params;
        WSADATA wsaData;
        SOCKET serverSocket = INVALID_SOCKET; 
        int addrlen = sizeof(serverAddress);

        int createKeys();
        int setupServerSocket(char *serverIP, u_short port);
};

// Public

Client::Client(std::string _name)
{
    name = _name;
}

int Client::start(void)
{
    int err;

    // Generate public and private keys
    //err = createKeys();

    // Initialize Winsock
    err = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (err != 0) {
        std::cout << "WSAStartup failed with error: " << err << std::endl;
        return 1;
    }

    // Creating IPv4 socket object
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cout << "Server socket setup failed with error: " << serverSocket << std::endl;
        return 1;
    }

    return 0;
}

int Client::connectServer(char *serverIP, u_short port)
{
    int err;

    err = setupServerSocket(serverIP, port);
    if (err != 0) {
        return 1;
    }

    return 0;
}

int Client::readServer(char *buffer)
{
    // Read in buffer
    int nBytes = recv(serverSocket, buffer, DEFAULT_BUFLEN, 0);

    return nBytes;
}

int Client::sendServer(const char *msg)
{
    // Send message to server
    send(serverSocket, msg, (int)strlen(msg), 0);

    return 0;
}

// Private

int Client::createKeys(void)
{
    // Generate keys
    params.GenerateRandomWithKeySize(rng, keySize);
    CryptoPP::RSA::PrivateKey _privateKey(params);
    CryptoPP::RSA::PublicKey _publicKey(params);
    privateKey = _privateKey;
    publicKey = _publicKey;

    // Generate certificate
    //cert.identity = name;
    //cert.publicKey = 

    return 0;
}

int Client::setupServerSocket(char *serverIP, u_short port)
{
    int err;

    // Setup server address type and port
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
 
    // Convert address from text to binary form
    err = inet_pton(AF_INET, serverIP, &serverAddress.sin_addr);
    if (err != 1) {
        std::cout << "Address conversion error: " << err << std::endl;
        return 1;
    }
 
    // Attempt a connection to the server
    err = connect(serverSocket, (struct sockaddr*)&serverAddress, addrlen);
    if (err != 0) {
        std::cout << "Connection to server failed: " << err << std::endl;
        return 1;
    }

    return 0;
}

//int Client::exchangeServerCert(void)
//{
//
//    return 0;
//}

//struct clientCert{
//    std::string identity;
//    int publicKey;
//};

// Main

int main(int argc, char* argv[])
{
    int err, nBytes;
    char *msg = "Hello Server!";
    char *serverIP = "127.0.0.1";
    u_short port = 8080;
    char buffer[DEFAULT_BUFLEN] = { 0 };

    Client alice("Alice");
    std::cout << "Alice\n ----------" << std::endl;

    err = alice.start();
    if (err != 0) { return 1; }
    std::cout << "Client started" << std::endl;

    err = alice.connectServer(serverIP, port);
    if (err != 0) { return 1; }
    std::cout << "Connected to server" << std::endl;

    err = alice.sendServer(msg);
    if (err != 0) { return 1; }
    std::cout << "From me: " << msg << std::endl;

    nBytes = alice.readServer(buffer);
    std::cout << "From server: " << buffer << std::endl;

    system("pause");
    return 0;
}
