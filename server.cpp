// Server source file for communicating with clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography
// https://www.daniweb.com/programming/software-development/threads/6811/winsock-multi-client-servers

#include "server.h"


/* ClientSession */


ClientSession::ClientSession(void) { }
ClientSession::ClientSession(SOCKET socket) { this->socket = socket; }
ClientSession::ClientSession(Certificate cert) { this->cert = cert; }
ClientSession::ClientSession(SOCKET socket, Certificate cert)
{
    this->socket = socket;
    this->cert   = cert;
}


/* Server */


Server::Server(void) { }

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

    // Put in passive listening mode
    err = listen(serverSocket, nBacklog);
    if (err != 0) {
        std::cerr << "Listen failed with error: " << err << std::endl;
        return 1;
    }

    // Set blocking type to non-blocking
    unsigned long b=1;
	ioctlsocket(serverSocket,FIONBIO,&b);

    return 0;
}

int Server::acceptClients(Certificate CACert)
{
    int err;
    SOCKET clientSocket;
    Certificate clientCert;

    // Accept any connections in the queue
    clientSocket = accept(serverSocket, (struct sockaddr*)&serverAddress, (int *)&addrlen);
    if (clientSocket == SOCKET_ERROR || clientSocket == 0) {
        return 1;
    }

    // Add client to client list
    ClientSession client(clientSocket);
    client.state = sendingCert;
    clients.push_back(client);

    printClients();

	return 0;
}

int Server::readClients(void)
{
    int err;
    char buffer[DEFAULT_BUFLEN] = { 0 };

    for(ClientSession &client : clients) {
        int nBytes = recv(client.socket, buffer, DEFAULT_BUFLEN, 0);

        if (nBytes > 0) {
            switch(client.state)
            {
                case disconnected:
                    std::cout << "Received message from disconnected client" << std::endl;
                    break;
                case sendingCert:
                    verifyClientCert(buffer, client);
                    sendServerCert(client);
                    break;
                case sendingChallenge:
                    verifyClientResponse(buffer, client);
                    std::cout << "Client verified" << std::endl;
                    break;
                case connected:
                    std::cout << "Received message from connected client" << std::endl;
                    break;
            }

            printClients();
        }
    }

	return 0;
}

void Server::printClients(void)
{
    std::cout << "\nName                | State" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    for(ClientSession client : clients) {
        std::cout << std::setw(20) << client.cert.subjectName << "| ";
        std::cout << std::setw(20) << clientStateStrings[client.state + 2] << std::endl;
    }
}


/* Server::Private */


int Server::verifyClientCert(std::string msg, ClientSession &client)
{
    int nBytes;
    bool isVerified;

    // 1(a) Read client certificate
    CertMSG clientMsg;
    AuthMSG clientAuth;
    clientAuth.deserialize(msg);

    // Extract certificate
    clientMsg.deserialize(clientAuth.msg);
    client.cert = clientMsg.cert;

    // 1(b) Verify digital signature
    isVerified = clientAuth.verify(client.cert.publicKey);
    if (isVerified == false) {
        client.state = unverified;
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // 1(c) Verify client certificate
    isVerified = clientMsg.cert.verify(CACert.publicKey);
    if (isVerified == false) {
        client.state = unverified;
        std::cerr << "Certificate did not match CA" << std::endl;
        return 1;
    }

    client.state = sendingChallenge;

    return 0;
}

int Server::sendServerCert(ClientSession &client)
{   
    int nBytes;

    // 2 Send server certificate
    CertMSG serverMsg(cert);
    client.serverChallenge = serverMsg.nonce;
    serverMsg.encryptNonce(client.cert.publicKey);
    AuthMSG serverAuth(&serverMsg, privateKey);

    nBytes = serverAuth.sendMSG(client.socket);
    if (nBytes == 0) { 
        std::cerr << "Server certificate could not be sent" << std::endl;
        return 1; 
    }

    return 0;
}

int Server::verifyClientResponse(std::string msg, ClientSession &client)
{
    int nBytes;
    std::string clientChallenge, clientResponse;

    // 3(a) Read new challenge-response
    ChallengeMSG clientCR;
    AuthMSG clientCRAuth;
    clientCRAuth.deserialize(msg);

    // Extract response
    clientCR.deserialize(clientCRAuth.msg);
    clientCR.decryptNonces(privateKey);
    clientChallenge = clientCR.challenge;
    clientResponse  = clientCR.response;

    // 3(b) Verify response
    if (client.serverChallenge != clientResponse) {
        std::cerr << "Client response did not match challenge" << std::endl;
        client.state = unverified;
        return 1;
    }

    client.serverChallenge.clear();

    // 4 Send challenge back
    ChallengeMSG serverCR(clientChallenge);
    serverCR.encryptNonces(client.cert.publicKey);
    AuthMSG serverCRAuth(&serverCR, privateKey);

    nBytes = serverCRAuth.sendMSG(client.socket);
    if (nBytes == 0) {
        std::cerr << "Server response could not be sent" << std::endl;
        return 1;
    }

    client.state = connected;

    return 0;
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
    server.CACert = CACert;
    std::cout << server.cert.subjectName << "\n ----------" << std::endl;

    err = server.start(serverIP, port);
    if (err != 0) { return 1; }
    std::cout << "Server started" << std::endl;

    while(true)
    {
        server.acceptClients(CACert);	//Receive connections
        //server.sendClients();		    //Send data to clients
        server.readClients();		    //Recive data from clients
    }

    system("pause");
    return 0;
}
