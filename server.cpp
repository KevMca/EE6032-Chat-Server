// Server source file for communicating with clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

#include "server.h"
#include "cert.h"
#include "protocol.h"


/* Public */


int Server::start(char *serverIP, u_short port)
{
    int err;
    char opt = 1;

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

    // Forcefully (SO_REUSEADDR) attaching socket to the port
    err = setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (err != 0) {
        std::cout << "Setting socket option (setsockopt) failed with error: " << err << std::endl;
        return 1;
    }

    // Forcefully attaching socket to the port and address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(serverIP);
    serverAddress.sin_port = htons(port);

    err = bind(serverSocket, (struct sockaddr*)&serverAddress, addrlen);
    if (err != 0) {
        std::cout << "Bind failed with error: " << err << std::endl;
        return 1;
    }

    return 0;
}

int Server::connectClient(void)
{
    int err;

    // Put in passive listening mode
    err = listen(serverSocket, nBacklog);
    if (err != 0) {
        std::cout << "Listen failed with error: " << err << std::endl;
        return 1;
    }

    // Accept the first connection on the queue and setup socket connection
    clientSocket = accept(serverSocket, (struct sockaddr*)&serverAddress, (int *)&addrlen);
    if (clientSocket == INVALID_SOCKET) {
        std::cout << "Client socket setup failed with error: " << clientSocket << std::endl;
        return 1;
    }

    return 0;
}

int Server::readClient(char *buffer)
{
    int nBytes = recv(clientSocket, buffer, DEFAULT_BUFLEN, 0);

    return nBytes;
}

int Server::sendClient(const char *msg)
{
    int nBytes = send(clientSocket, msg, (int)strlen(msg), 0);

    return nBytes;
}


/* Main */


int main(int argc, char* argv[])
{
    int err, nBytes;

    // Certificates
    const char *privateKeyName = "certs/alice_private.der";
    const char *publicKeyName  = "certs/alice_public.der";
    const char *publicCAName  = "certs/root_public.der";

    // IP Information
    char *serverIP = "127.0.0.1";
    u_short port = 8080;
    char buffer[DEFAULT_BUFLEN] = { 0 };

    Server server;
    std::cout << "Server\n ----------" << std::endl;

    err = server.start(serverIP, port);
    if (err != 0) { return 1; }
    std::cout << "Server started" << std::endl;

    err = server.connectClient();
    if (err != 0) { return 1; }
    std::cout << "Client accepted" << std::endl;

    // Read certificate

    /*nBytes = server.readClient(buffer);
    std::cout << "From client: " << buffer << std::endl;

    err = server.sendClient(msg);
    if (err != 0) { return 1; }
    std::cout << "From me: " << msg << std::endl;*/

    system("pause");
    return 0;
}
