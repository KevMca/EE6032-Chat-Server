// Copyright 2023 Kevin McAndrew
// Client header file for communicating with server and other clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

#ifndef CLIENT_H_
#define CLIENT_H_

// Include other C libraries
#include <conio.h>

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

// Include other C++ libraries
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

#include "./cert.h"
#include "./protocol.h"

// Client session class for other clients connected to the server
// Example:
//     ClientSession(cert, socket);
class ClientSession {
 public:
    Certificate cert;
    std::string partialKey;

    ClientSession();
    explicit ClientSession(Certificate cert);
};

// List of possible states the client can be in
//  Startup: Not connected to the server yet
//  Connected: Connected to the server and verified it
//  Agreement: Exchanging partial keys with other clients
//  Chatting: A shared secret is established and chat messages can be sent
enum ClientState { startup, connected, agreement, chatting };

// Client class specification
// Example:
//     Client alice;
//     int err = alice.start();
//     if (err != 0) { return 1; }
//     err = server.connectServer(serverIP, port);
//     if (err != 0) { return 1; }
class Client {
 public:
    ClientState state = startup;
    SOCKET serverSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddress;
    CryptoPP::RSA::PrivateKey privateKey;
    Certificate cert;
    Certificate serverCert;
    std::vector<ClientSession> clients;
    std::string sharedKey;

    // Empty constructor for client
    Client(void);

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

    // Reads the socket buffer and parses the message from the server
    // Inputs -> CACert: the certificate of the certificate authority
    // Returns -> 0 if no errors, 1 if there was an error
    int parseServerMessage(Certificate CACert);

    // Reads a certificate from the server and checks that it is valid
    // Inputs -> messageAuth: The message that contains the certificate
    //           CACert: The certificate of the issuing certificate authority
    // Outputs -> newCert: The verified certificate
    // Returns -> 0 if no errors, 1 if any of the verification checks fail
    int readCertificate(AppMSG messageAuth, Certificate CACert, Certificate &newCert);

    // Generates a partial key and sends it to the other clients
    // Returns -> 0 if no errors, 1 if there was an error
    int sendPartialKey(void);

    // Parses a partial key message from another client
    // Inputs -> messageAuth: The message that contains the partial key
    // Outputs -> partialKey: The partial key contained inside the message
    // Returns -> 0 if no errors, 1 if any of the message checks fail
    int readPartialKey(AppMSG messageAuth, std::string &partialKey);

    // Sends an encrypted chat message to all other clients
    // Inputs -> message: The chat message to be sent
    // Returns -> 0 if no errors, 1 if there was an error sending the message
    int sendChatMessage(std::string message);

    // Reads an encrypted chat message from another client and prints it
    // Inputs -> messageAuth: The message that contains the encrypted chat message
    // Outputs -> message: The decrypted message
    // Returns -> 0 if no errors, 1 if there was an error
    int readChatMessage(AppMSG messageAuth, std::string &message);

    // Prints the current table of other clients
    void printClients(void);

    // Returns a client session, given a subject name
    // Inputs -> subjectName: The name of the requested client
    // Outputs -> session: The returned ClientSession
    // Returns -> 0 if no errors, 1 if the client is not in the current list of clients
    int getClientSession(std::string subjectName, ClientSession **session);

 private:
    WSADATA wsaData;
    int addrlen = sizeof(serverAddress);

    // Bitwise OR's the current shared key with the incoming client partial key
    // Inputs -> clientPartialKey: the incoming partial key
    // Returns -> 0 if no errors, 1 if the partial keys have different sizes
    int incorporatePartialKey(std::string clientPartialKey);

    // Checks if all of the clients in the client list have sent their partial keys
    // Returns -> true if agreement is complete, false if agreement is not complete
    bool isAgreementComplete(void);

    // Adds a client certificate to the list of other clients, if it doesn't already exist
    // Inputs -> clientCert: the certificate of a different client connected to the server
    // Returns -> true if certificate already, false if certificate already existed
    bool updateClients(Certificate clientCert);

    // Connects to a server with a specific IP address and port
    // Inputs -> serverIP: the IP address of the server
    //           port: the port number of the server
    // Returns -> 0 if no errors, 1 if there was an error
    int setupServerSocket(char *serverIP, u_short port);
};

#endif  // CLIENT_H_
