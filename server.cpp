// Server source file for communicating with clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography
// https://www.daniweb.com/programming/software-development/threads/6811/winsock-multi-client-servers

#include "server.h"
#include "logging.h"


/* Parameters */


// Log filename
std::string logName = "logs/server.log";

// IP Information
char *serverIP = "127.0.0.1";
u_short port = 8080;

// Certificates
const char *privateName = "certs/server_private.der";
const char *publicName  = "certs/server_public.der";
const char *publicCAName  = "certs/root_public.der";


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
        std::cerr << "WSAStartup failed with error: " << err << std::endl;
        return 1;
    }

    // Creating IPv4 socket object
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "Server socket setup failed with error: " << serverSocket << std::endl;
        return 1;
    }

    // Forcefully (SO_REUSEADDR) attaching socket to the port
    err = setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (err != 0) {
        std::cerr << "Setting socket option (setsockopt) failed with error: " << err << std::endl;
        return 1;
    }

    // Forcefully attaching socket to the port and address
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_addr.s_addr = inet_addr(serverIP);
    serverAddress.sin_port = htons(port);

    err = bind(serverSocket, (struct sockaddr*)&serverAddress, addrlen);
    if (err != 0) {
        std::cerr << "Bind failed with error: " << err << std::endl;
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

    Logger("Server started", logName);

    return 0;
}

int Server::readClientConnections(Certificate CACert)
{
    int err;
    SOCKET clientSocket;

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
                    Logger("Received message from disconnected client", logName);
                    break;
                case sendingCert:
                    err = verifyClientCert(buffer, client);
                    if (err != 0) { return 1; }
                    sendServerCert(client);
                    Logger("Received cert from " + client.cert.subjectName, logName);
                    break;
                case sendingChallenge:
                    err = verifyClientResponse(buffer, client);
                    if (err != 0) { return 1; }
                    sendClientUpdate();
                    Logger("Client verified", logName);
                    break;
                case connected:
                    err = echoMessage(buffer);
                    if (err != 0) { return 1; }
                    break;
            }

            printClients();
        }
    }

	return 0;
}

void Server::printClients(void)
{
    system("cls");
    std::cout << this->cert.subjectName << "\n----------" << std::endl;

    // Print client list
    std::cout << "\nClients             | State" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    for(ClientSession client : clients) {
        std::cout << std::setw(20) << client.cert.subjectName << "| ";
        std::cout << std::setw(20) << clientStateStrings[client.state + 2] << std::endl;
    }

    // Print log file if it is not empty
    std::ifstream f(logName);
    if (f.peek() != std::ifstream::traits_type::eof())
    {
        std::cout << std::endl << f.rdbuf();
    }
}


/* Server::Private */


int Server::verifyClientCert(std::string msg, ClientSession &client)
{
    int nBytes;
    bool isVerified;

    // 1(a) Read client certificate
    CertMSG clientMsg;
    AppMSG clientAuth;
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

    // 2 Send server certificate and a challenge
    CertMSG serverMsg(cert);
    ChallengeMSG serverChallenge;
    client.Ns = serverChallenge.generateChallenge();
    serverChallenge.encryptNonces(client.cert.publicKey);

    // Cert, N, {H(Cert, N)}_ks^-1
    AppMSG serverAuth(serverMsg.serialize() + ";" + serverChallenge.serialize(), cert.subjectName, client.cert.subjectName);
    serverAuth.sign(privateKey);

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
    bool isVerified;
    std::string clientChallenge, clientResponse;

    // 3(a) Read new challenge-response
    ChallengeMSG clientCR;
    AppMSG clientCRAuth;
    clientCRAuth.deserialize(msg);

    // 3(b) Verify digital signature
    isVerified = clientCRAuth.verify(client.cert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // Extract response
    clientCR.deserialize(clientCRAuth.msg);
    clientCR.decryptNonces(privateKey);
    clientChallenge = clientCR.challenge;
    clientResponse  = clientCR.response;

    // 3(b) Verify response
    if (client.Ns != clientResponse) {
        std::cerr << "Client response did not match challenge" << std::endl;
        client.state = unverified;
        return 1;
    }

    client.Ns.clear();

    // 4 Send challenge back
    ChallengeMSG serverCR(clientChallenge);
    serverCR.encryptNonces(client.cert.publicKey);
    AppMSG serverCRAuth(&serverCR, cert.subjectName, client.cert.subjectName);
    serverCRAuth.sign(privateKey);

    nBytes = serverCRAuth.sendMSG(client.socket);
    if (nBytes == 0) {
        std::cerr << "Server response could not be sent" << std::endl;
        return 1;
    }

    client.state = connected;

    return 0;
}

int Server::sendClientUpdate(void)
{   
    for(ClientSession &client : clients) {
        if(client.state == connected)
        {
            sendClientSessions(client);
        }
    }

    return 0;
}

int Server::sendClientSessions(ClientSession &recipient)
{
    int nBytes;

    for(ClientSession &client : clients) {
        if (client.cert.subjectName != recipient.cert.subjectName)
        {
            CertMSG serverMsg(client.cert);
            AppMSG serverAuth(&serverMsg, cert.subjectName, recipient.cert.subjectName);
            serverAuth.sign(privateKey);

            nBytes = serverAuth.sendMSG(recipient.socket);
            if (nBytes == 0) { 
                std::cerr << "Client certificate could not be sent" << std::endl;
                return 1;
            }
        }
    }

    return 0;
}

int Server::echoMessage(std::string msg)
{
    int nBytes, err;
    bool isVerified;

    ClientSession sender, recipient;

    // Deserialize the message from the client
    AppMSG clientMsg;
    clientMsg.deserialize(msg);

    // Perform an authenticated integrity check
    if (clientMsg.type != "ChatMSG")
    {
        getClientSession(clientMsg.source, sender);
        isVerified = clientMsg.verify(sender.cert.publicKey);
        if (isVerified == false) {
            std::cerr << "Message digital signature did not match" << std::endl;
            return 1;
        }
    }

    Logger("Received " + clientMsg.type + ", source: " + clientMsg.source + ", destination: " + clientMsg.destination, logName);

    // If the destination is not specified, broadcast the message to everyone except the source
    if (clientMsg.destination.empty())
    {
        for(ClientSession &client : clients) 
        {
            if (client.cert.subjectName != clientMsg.source)
            {
                nBytes = clientMsg.sendMSG(client.socket);
                if (nBytes == 0) { 
                    std::cerr << "Client message could not be echoed" << std::endl;
                    return 1;
                }
            }
        }
    }
    // If the destination is specified, send to that specific client only
    else 
    {
        err = getClientSession(clientMsg.destination, recipient);
        if(err != 0)
        {
            std::cerr << "The destination for message is unknown to the server" << std::endl;
            return 1;
        }

        nBytes = clientMsg.sendMSG(recipient.socket);
        if (nBytes == 0) { 
            std::cerr << "Client message could not be echoed" << std::endl;
            return 1;
        }
    }
    

    return 0;
}

int Server::getClientSession(std::string subjectName, ClientSession &session)
{
    for(ClientSession &client : clients) {
        if(client.cert.subjectName == subjectName)
        {
            session = client;
            return 0;
        }
    }

    return 1;
}


/* Main */


int main(int argc, char* argv[])
{
    int err, nBytes;

    // Clear log file
    std::ofstream file(logName);
    file.close();

    // Read CA certificate
    Certificate CACert(publicCAName);

    // Start server
    Server server(privateName, publicName);
    server.CACert = CACert;

    server.printClients();

    err = server.start(serverIP, port);
    if (err != 0) { return 1; }

    while(true)
    {
        server.readClientConnections(CACert);	//Handle any connection requests
        err = server.readClients();		        //Receive data from clients
        if (err != 0) { return 1; }
    }

    system("pause");
    return 0;
}
