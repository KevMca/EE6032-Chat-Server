// Client source file for communicating with server and other clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

#include "client.h"


/* Public */


Client::Client(void)
{

}

Client::Client(const char *privateName, const char *publicName)
{
    Certificate cert(publicName);
    this->cert = cert;
    privateKey = Certificate::readKey<CryptoPP::RSA::PrivateKey>(privateName);
}

int Client::start(void)
{
    int err;

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

int Client::connectServer(char *serverIP, u_short port, Certificate CACert)
{
    int err, nBytes;
    bool isVerified;

    err = setupServerSocket(serverIP, port);
    if (err != 0) {
        return 1;
    }

    // 1 Send client certificate
    CertMSG clientMsg(cert);
    AuthMSG clientAuth(&clientMsg, privateKey);

    nBytes = clientAuth.sendMSG(serverSocket);
    if (nBytes == 0) {
        std::cerr << "Client certificate could not be sent" << std::endl;
        return 1;
    }

    // 2(a) Receive server certificate
    CertMSG serverMsg;
    AuthMSG serverAuth;
    nBytes = serverAuth.readMSG(serverSocket);
    if (nBytes == 0) {
        std::cerr << "Server certificate could not be read" << std::endl;
        return 1;
    }

    // Extract certificate
    serverMsg.deserialize(serverAuth.msg);
    serverMsg.decryptNonce(privateKey);
    serverCert = serverMsg.cert;

    // 2(b) Verify digital signature
    isVerified = serverAuth.verify(serverCert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // 2(c) Verify server certificate
    isVerified = serverMsg.cert.verify(CACert.publicKey);
    if (isVerified == false) {
        std::cerr << "Certificate did not match CA" << std::endl;
        return 1;
    }

    // 3 Send challenge-response

    // 4(a) Read response

    // 4(b) Verify response

    return 0;
}

int Client::readServer(char *buffer)
{
    int nBytes = recv(serverSocket, buffer, DEFAULT_BUFLEN, 0);

    return nBytes;
}

int Client::sendServer(const char *msg)
{
    int nBytes = send(serverSocket, msg, (int)strlen(msg), 0);

    return nBytes;
}


/* Private */


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


/* Main */


int main(int argc, char* argv[])
{
    int err, nBytes;

    // IP Information
    char *serverIP = "127.0.0.1";
    u_short port = 8080;
    char buffer[DEFAULT_BUFLEN] = { 0 };

    // Certificates
    const char *privateName = "certs/alice_private.der";
    const char *publicName  = "certs/alice_public.der";
    const char *publicCAName  = "certs/root_public.der";
    
    // Read CA certificate
    Certificate CACert(publicCAName);

    Client client(privateName, publicName);
    std::cout << client.cert.subjectName << "\n ----------" << std::endl;

    err = client.start();
    if (err != 0) { return 1; }
    std::cout << "Client started" << std::endl;

    err = client.connectServer(serverIP, port, CACert);
    if (err != 0) { return 1; }
    std::cout << "Connected to server" << std::endl;

    system("pause");
    return 0;
}
