// Client source file for communicating with server and other clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

#include "client.h"


/* ClientSession */


ClientSession::ClientSession(void) { }
ClientSession::ClientSession(Certificate cert) { this->cert = cert; }


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
    std::string clientChallenge, serverChallenge, serverResponse;

    err = setupServerSocket(serverIP, port);
    if (err != 0) {
        return 1;
    }

    // 1 Send client certificate
    CertMSG clientMsg(cert);
    AuthMSG clientAuth(&clientMsg, cert.subjectName, "Server", privateKey);

    nBytes = clientAuth.sendMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Client certificate could not be sent" << std::endl;
        return 1;
    }
    std::cerr << "Client certificate sent: " << nBytes << std::endl;

    // 2(a) Receive server certificate
    CertMSG serverMsg;
    AuthMSG serverAuth;
    nBytes = serverAuth.readMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Server certificate could not be read" << std::endl;
        return 1;
    }

    // Extract certificate
    serverMsg.deserialize(serverAuth.msg);
    serverMsg.decryptNonce(privateKey);
    serverChallenge = serverMsg.nonce;
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
    ChallengeMSG clientCR(serverChallenge);
    clientCR.generateChallenge();
    clientChallenge = clientCR.challenge;
    clientCR.encryptNonces(serverCert.publicKey);
    AuthMSG clientCRAuth(&clientCR, cert.subjectName, serverCert.subjectName, privateKey);

    nBytes = clientCRAuth.sendMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Client challenge-response could not be sent" << std::endl;
        return 1;
    }

    // 4(a) Read response
    ChallengeMSG serverCR;
    AuthMSG serverCRAuth;

    nBytes = serverCRAuth.readMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Server response could not be read" << std::endl;
        return 1;
    }

    // Extract response
    serverCR.deserialize(serverCRAuth.msg);
    serverCR.decryptNonces(privateKey);
    serverResponse = serverCR.response;

    // 4(b) Verify response
    if (clientChallenge != serverResponse) {
        std::cerr << "Server response did not match challenge" << std::endl;
        return 1;
    }

    state = ready;

    return 0;
}

int Client::readServer(Certificate CACert)
{
    int nBytes, err;
    char buffer[DEFAULT_BUFLEN] = { 0 };
    
    nBytes = recv(serverSocket, buffer, DEFAULT_BUFLEN, 0);
    if (nBytes <= 0) {
        std::cerr << "Server message could not be read" << std::endl;
        return 1;
    }

    AuthMSG messageAuth;
    messageAuth.deserialize(buffer);

    if(messageAuth.source == "Server") {
        // Server source
        if(messageAuth.type == "CertMSG") {
            // Read client certificate
            Certificate newCert;
            readCertificate(messageAuth, CACert, newCert);

            // Update client list
            bool updated = updateClients(newCert);
            if(updated) { printClients(); }
        }
    } 
    else {
        // Client source
        if(messageAuth.type == "AgreementMSG") {

            std::string input;

            if (state == ready)
            {
                std::cout << messageAuth.source << " is inviting you to chat. Do you accept? (y/n): " << std::endl;
                std::cin >> input;
                if (input != "y")
                {
                    return 1;
                }
                // send nonce to other users through server
                sendPartialKey();
                state = agreeing;
            }

            // Read nonce
            std::string clientPartialKey;
            readPartialKey(messageAuth, clientPartialKey);
            std::cout << "Partial key received: " << messageAuth.source << std::endl;

            // Save partial key to client list
            ClientSession *client;
            err = getClientSession(messageAuth.source, &client);
            if (err != 0) {
                std::cerr << "The destination for message is unknown to the server" << std::endl;
                return 1;
            }
            client->partialKey = clientPartialKey;

            // Incorporate other client's nonce into current nonce
            incorporatePartialKey(clientPartialKey);

            // If all partial keys are received
            if (isAgreementComplete())
            {
                std::cout << partialKey << std::endl;
                std::cout << "Agreement complete" << std::endl;
            }
        }
    }

    return 0;
}

int Client::sendPartialKey(void)
{
    int err, nBytes;
    bool isVerified;
    std::string clientChallenge, serverChallenge, serverResponse;

    // Create partial key
    AgreementMSG baseMsg;
    baseMsg.generateNonce();
    partialKey = baseMsg.nonce;

    // Send key to each client
    for(ClientSession client : clients) {
        // Encrypt nonce for the destination client
        AgreementMSG clientMsg = baseMsg;
        clientMsg.encryptNonce(client.cert.publicKey);

        // Create authenticated integrity message
        AuthMSG clientAuth(&clientMsg, cert.subjectName, client.cert.subjectName, privateKey);

        nBytes = clientAuth.sendMSG(serverSocket);
        if (nBytes <= 0) {
            std::cerr << "Client certificate could not be sent" << std::endl;
            return 1;
        }
        std::cerr << "Partial key sent to: " << client.cert.subjectName << std::endl;
    }

    return 0;
}

int Client::readPartialKey(AuthMSG messageAuth, std::string &partialKey)
{
    int err;
    bool isVerified;

    // Get session for sender
    ClientSession *sender;
    err = getClientSession(messageAuth.source, &sender);
    if (err != 0) {
        std::cerr << "The destination for message is unknown to the server" << std::endl;
        return 1;
    }

    // Verify digital signature
    isVerified = messageAuth.verify(sender->cert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // Read in message and decrypt nonce
    AgreementMSG clientMsg;
    clientMsg.deserialize(messageAuth.msg);
    clientMsg.decryptNonce(privateKey);
    partialKey = clientMsg.nonce;

    return 0;
}

int Client::readCertificate(AuthMSG messageAuth, Certificate CACert, Certificate &newCert)
{
    // Verify digital signature
    bool isVerified = messageAuth.verify(serverCert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // Extract certificate message
    CertMSG messageCert;
    messageCert.deserialize(messageAuth.msg);
    newCert = messageCert.cert;

    // Verify server certificate
    isVerified = newCert.verify(CACert.publicKey);
    if (isVerified == false) {
        std::cerr << "Certificate did not match CA" << std::endl;
        return 1;
    }

    return 0;
}

int Client::incorporatePartialKey(std::string clientPartialKey)
{
    // Check if incoming partial key has the same length
    if (partialKey.length() != clientPartialKey.length())
    {
        std::cerr << "Input partial key is not the same length as the current partial key" << std::endl;
        return 1;
    }

    // Bitwise OR the current partial key with the incoming client partial key
    for (int i = 0; i < partialKey.length(); i++) {
        partialKey[i] |= clientPartialKey[i];
    }

    return 0;
}

bool Client::isAgreementComplete(void)
{
    for(ClientSession &client : clients) {
        if(client.partialKey.empty())
        {
            return false;
        }
    }
    return true;
}

bool Client::updateClients(Certificate &clientCert)
{
    bool exists = false;

    for(ClientSession client : clients) {
        if(client.cert.subjectName == clientCert.subjectName)
        {
            exists = true;
            break;
        }
    }

    if(exists == false) {
        ClientSession newSession(clientCert);
        clients.push_back(newSession);
    }

    return !exists;
}

void Client::printClients(void)
{
    std::cout << "\nName" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    for(ClientSession client : clients) {
        std::cout << client.cert.subjectName << std::endl;
    }
}

int Client::getClientSession(std::string subjectName, ClientSession **session)
{
    for(ClientSession &client : clients) {
        if(client.cert.subjectName == subjectName)
        {
            *(session) = &client;
            return 0;
        }
    }

    return 1;
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
    std::string stem = "certs/";
    stem.append(argv[1]);
    std::string privateString = stem + std::string("_private.der");
    std::string publicString  = stem + std::string("_public.der");
    const char *privateName   = privateString.c_str();
    const char *publicName    = publicString.c_str();
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

    // Refresh the screen with current users

    // Listen for messages from server
    while(1) 
    {
        unsigned long nAvailable;
        ioctlsocket(client.serverSocket, FIONREAD, &nAvailable);

        // Receive socket
        if(nAvailable > 0)
        {   
            err = client.readServer(CACert);
            if (err != 0) { return 1; }
        }

        // Receive keyboard input
        if (_kbhit()) 
        {
            std::string input;
            std::cin >> input;

            if (client.state != agreeing)
            {
                // If the user wants to connect
                if(input == "y") {
                    client.state = agreeing;
                    // send nonce to other users through server
                    client.sendPartialKey();
                }
                // Otherwise close the program 
                else {
                    return 1;
                }
            }
        }
        
    }

    // Listen for messages from server
    while(1) {
        // Receive socket
        // If message received, decrypt and print
        
        // Receive keyboard
        // If input received, print, encrypt and send
    }

    // Wait for input from user to see other clients connected to server
    //std::cout << "Press ENTER to see other connected users: ";
    //std::cin.ignore();
    //client.requestUsers();

    //std::cout << "Press ENTER to connect to these users: ";
    //std::cin.ignore();
    //client.requestUsers();
    
    // THen wait for input to connect to other clients

    system("pause");
    return 0;
}
