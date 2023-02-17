// Server source file for communicating with clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

#include "server.h"
#include "cert.h"


/* Public */


Server::Server(void)
{

}

Server::Server(const char *privateName, const char *publicName)
{
    Certificate cert(publicName);
    this->cert = cert;
    privateKey = Certificate::readKey<CryptoPP::RSA::PrivateKey>(privateName);
}

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

int Server::listenClient(void)
{
    int err;

    // Put in passive listening mode
    err = listen(serverSocket, nBacklog);
    if (err != 0) {
        std::cerr << "Listen failed with error: " << err << std::endl;
        return 1;
    }

    // Accept the first connection on the queue and setup socket connection
    clientSocket = accept(serverSocket, (struct sockaddr*)&serverAddress, (int *)&addrlen);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "Client socket setup failed with error: " << clientSocket << std::endl;
        return 1;
    }

    return 0;
}

int Server::connectClient(Certificate CACert)
{
    int err, nBytes;
    bool isVerified;
    
    // 1(a) Read client certificate
    CertMSG clientMsg;
    AuthMSG clientAuth;
    nBytes = clientAuth.readMSG(clientSocket);
    if (nBytes == 0) {
        std::cerr << "Client certificate could not be read" << std::endl;
        return 1;
    }

    // Extract certificate
    clientMsg.deserialize(clientAuth.msg);
    clientCert = clientMsg.cert;

    // 1(b) Verify digital signature
    isVerified = clientAuth.verify(clientCert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // 1(c) Verify client certificate
    isVerified = clientMsg.cert.verify(CACert.publicKey);
    if (isVerified == false) {
        std::cerr << "Certificate did not match CA" << std::endl;
        return 1;
    }
    
    // 2 Send server certificate
    CertMSG serverMsg(cert);
    serverMsg.encryptNonce(clientCert.publicKey);
    AuthMSG serverAuth(&serverMsg, privateKey);

    nBytes = serverAuth.sendMSG(clientSocket);
    if (nBytes == 0) { 
        std::cerr << "Server certificate could not be sent" << std::endl;
        return 1; 
    }

    // 3(a) Read new challenge-response

    // 3(b) Verify response

    // 4 Send challenge back

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

    // IP Information
    char *serverIP = "127.0.0.1";
    u_short port = 8080;

    // Certificates
    const char *privateName = "certs/server_private.der";
    const char *publicName  = "certs/server_public.der";
    const char *publicCAName  = "certs/root_public.der";

    // Read CA certificate
    Certificate CACert(publicCAName);

    // Start server
    Server server(privateName, publicName);
    std::cout << server.cert.subjectName << "\n ----------" << std::endl;

    err = server.start(serverIP, port);
    if (err != 0) { return 1; }
    std::cout << "Server started" << std::endl;

    err = server.listenClient();
    if (err != 0) { return 1; }
    std::cout << "Client accepted" << std::endl;

    err = server.connectClient(CACert);
    if (err != 0) { return 1; }
    std::cout << "Verified client" << std::endl;
    std::cout << "Connected with: " << server.clientCert.subjectName << std::endl;

    system("pause");
    return 0;
}
