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

#include <iomanip>
#include "cert.h"
#include "protocol.h"

char *clientStateStrings[] = 
{
    "unverified",
    "disconnected",
    "sendingCert",
    "sendingChallenge",
    "connected"
};

enum clientState
{
    unverified = -2,
    disconnected = -1,
    sendingCert = 0,
    sendingChallenge = 1,
    connected = 2
};

// Client session class specification
// Example:
//     ClientSession(cert, socket);
class ClientSession {
    public:
        clientState state = disconnected;
        Certificate cert;
        SOCKET socket = INVALID_SOCKET;
        std::string Ns;

        ClientSession();
        ClientSession(SOCKET socket);
        ClientSession(Certificate cert);
        ClientSession(SOCKET socket, Certificate cert);
};

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
        Certificate CACert;
        std::vector<ClientSession> clients;

        explicit Server(void);

        // Constructor for server if private and public keys are known
        // Inputs -> privateName: location of the private key file for the server
        //           publicName: location of the public key file for the server
        explicit Server(const char *privateName, const char *publicName);

        // Starts the server socket and attaches to port and address
        // Inputs -> serverIP: the IP address of the server
        //           port: the port of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int start(char *serverIP, u_short port);

        // Checks if there are any pending connections and start the verification process for the client
        // Inputs -> CACert: the certificate of the certificate authority
        // Returns -> 0 if a client was accepted, 1 if there was an error or no client was accepted
        int readClientConnections(Certificate CACert);

        // Sends any buffered messages to clients
        // Inputs -> serverIP: the IP address of the server
        //           port: the port of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int sendClients();

        // Reads if there are any incoming messages from clients
        // Inputs -> serverIP: the IP address of the server
        //           port: the port of the server
        // Returns -> 0 if no errors, 1 if there was an error
        int readClients(void);

        // Prints the current table of clients
        void printClients(void);

    private:
        WSADATA wsaData;
        SOCKET serverSocket = INVALID_SOCKET;
        int addrlen = sizeof(serverAddress);

        // Reads a client's certificate, validates it and validates the authenticity of the client
        // Inputs -> msg: the certificate message with authorised integrity check
        //           client: the client that sent their certificate
        // Returns -> 0 if no errors, 1 if authentication or verification failed
        int verifyClientCert(std::string msg, ClientSession &client);

        // Sends the server's certificate and challenge to a client
        // Inputs -> client: the client to send the certificate to
        // Returns -> 0 if no errors, 1 if message could not be sent
        int sendServerCert(ClientSession &client);

        // Verify the client's response and send the servers response
        // Inputs -> msg: the challenge-response message with authorised integrity check
        //           client: the client to send the response to
        // Returns -> 0 if no errors, 1 if the response did not match challenge or message could not be sent
        int verifyClientResponse(std::string msg, ClientSession &client);

        // Sends the certificates of all of the connected clients to the each client
        // Returns -> 0
        int sendClientUpdate(void);

        // Sends the certificates of all of the connected clients to a single client
        // Inputs -> recipient: the session of the client to send the update to
        //           client: the client to send the response to
        // Returns -> 0 if no errors, 1 if the certificate could not be sent
        int sendClientSessions(ClientSession &recipient);

        // Reads a message from a client and passes on the message to the
        // intended recipient. If no destination is provided in the message
        // it is broadcast to every client
        // Inputs -> msg: a string containing the serialised message
        // Returns -> 0 if no errors, 1 if the message could not be sent, or the destination is unknown
        int echoMessage(std::string msg);

        // Retrieves a client session, given the client's name
        // Inputs -> subjectName: the name of the client
        // Outputs -> session: the session of the client
        // Returns -> 0 if no errors, 1 if the client name does not match any known client session
        int getClientSession(std::string subjectName, ClientSession &session);
};
