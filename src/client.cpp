// Copyright 2023 Kevin McAndrew
// Client source file for communicating with server and other clients
//
// Sources:
// https://www.geeksforgeeks.org/socket-programming-cc/ (Linux server-client code base)
// https://learn.microsoft.com/en-us/windows/win32/winsock/complete-server-code (Winsock example)
// https://www.cryptopp.com/wiki/RSA_Cryptography

#include "./client.h"
#include "../include/logging.h"

/* Parameters */


// IP Information
char *serverIP = "127.0.0.1";
u_short port = 8080;

// Certificates
const char *publicCAName  = "certs/root_public.der";


/* ClientSession */


ClientSession::ClientSession(void) { }
ClientSession::ClientSession(Certificate cert) { this->cert = cert; }


/* Public */


Client::Client(void) {}

Client::Client(const char *privateName, const char *publicName) {
    Certificate cert(publicName);
    this->cert = cert;
    privateKey = Certificate::readKey<CryptoPP::RSA::PrivateKey>(privateName);
}

int Client::start(void) {
    int err;

    // Initialize Winsock
    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
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

int Client::connectServer(char *serverIP, u_short port, Certificate CACert) {
    int err, nBytes;
    bool isVerified;
    std::string Nc, Ns, serverResponse;

    err = setupServerSocket(serverIP, port);
    if (err != 0) {
        return 1;
    }

    // 1 Send client certificate
    CertMSG clientMsg(cert);
    AppMSG clientAuth(&clientMsg, cert.subjectName, serverCert.subjectName);
    clientAuth.sign(privateKey);

    nBytes = clientAuth.sendMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Client certificate could not be sent" << std::endl;
        return 1;
    }
    std::cerr << "Client certificate sent" << std::endl;

    // 2. Receive server certificate
    std::string serverCertString, serverChallengeString;
    ChallengeMSG serverChallengeMsg;
    CertMSG serverCertMsg;
    AppMSG serverAuth;
    nBytes = serverAuth.readMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Server certificate could not be read" << std::endl;
        return 1;
    }

    // 2(a) Deserialise message
    std::stringstream ss(serverAuth.msg);
    std::getline(ss, serverCertString, ';');
    std::getline(ss, serverChallengeString, ';');

    serverCertMsg.deserialize(serverCertString);
    serverCert = serverCertMsg.cert;

    serverChallengeMsg.deserialize(serverChallengeString);
    serverChallengeMsg.decryptNonces(privateKey);
    Ns = serverChallengeMsg.challenge;

    // 2(b) Verify digital signature
    isVerified = serverAuth.verify(serverCert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // 2(c) Verify server certificate
    isVerified = serverCertMsg.cert.verify(CACert.publicKey);
    if (isVerified == false) {
        std::cerr << "Certificate did not match CA" << std::endl;
        return 1;
    }

    // 3. Send challenge-response
    ChallengeMSG clientCR(Ns);
    clientCR.generateChallenge();
    Nc = clientCR.challenge;
    clientCR.encryptNonces(serverCert.publicKey);
    AppMSG clientCRAuth(&clientCR, cert.subjectName, serverCert.subjectName);
    clientCRAuth.sign(privateKey);

    nBytes = clientCRAuth.sendMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Client challenge-response could not be sent" << std::endl;
        return 1;
    }

    // 4(a) Read response
    ChallengeMSG serverCR;
    AppMSG serverCRAuth;

    nBytes = serverCRAuth.readMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Server response could not be read" << std::endl;
        return 1;
    }

    // 4(b) Verify digital signature
    isVerified = serverAuth.verify(serverCert.publicKey);
    if (isVerified == false) {
        std::cerr << "Message digital signature did not match" << std::endl;
        return 1;
    }

    // Extract response
    serverCR.deserialize(serverCRAuth.msg);
    serverCR.decryptNonces(privateKey);
    serverResponse = serverCR.response;

    // 4(c) Verify response
    if (Nc != serverResponse) {
        std::cerr << "Server response did not match challenge" << std::endl;
        return 1;
    }

    state = connected;

    return 0;
}

int Client::parseServerMessage(Certificate CACert) {
    int nBytes, err;
    char buffer[DEFAULT_BUFLEN] = { 0 };

    nBytes = recv(serverSocket, buffer, DEFAULT_BUFLEN, 0);
    if (nBytes <= 0) {
        std::cerr << "Server message could not be read" << std::endl;
        return 1;
    }

    AppMSG messageAuth;
    messageAuth.deserialize(buffer);

    // If the message is coming from the server
    if (messageAuth.source == "Server") {
        if (messageAuth.type != "CertMSG") {
            std::cerr << "Unexpected message from server. Expected a certificate." << std::endl;
            return 1;
        }

        Certificate newCert;
        err = readCertificate(messageAuth, CACert, newCert);
        if (err != 0) {
            std::cerr << "The incoming certificate message is invalid" << std::endl;
            return 1;
        }

        bool updated = updateClients(newCert);
        if (updated) { printClients(); }
    } else {
        // If the message is coming from another client
        if (messageAuth.type == "PartialKeyMSG" && state != chatting) {
            // If the other client is sending a partial key
            if (state == connected) {
                // If the agreement process has not started yet
                std::string input;
                std::cout << messageAuth.source << " is inviting you to chat. Would you like to proceed? (y/n): " << std::endl;
                std::cin >> input;
                if (input != "y") { return 1; }

                // Send partial key to other users, by sending it through the server
                sendPartialKey();
                state = agreement;
            }

            // Read incoming partial key
            std::string clientPartialKey;
            err = readPartialKey(messageAuth, clientPartialKey);
            if (err != 0) {
                std::cerr << "The incoming partial key message has an invalid digital signature" << std::endl;
                return 1;
            }
            std::cout << "Partial key received: " << messageAuth.source << std::endl;

            // Save partial key to client list
            ClientSession *client;
            err = getClientSession(messageAuth.source, &client);
            if (err != 0) {
                std::cerr << "The source of the partial key is unknown" << std::endl;
                return 1;
            }
            client->partialKey = clientPartialKey;

            // Incorporate other client's partial key into current secret key
            incorporatePartialKey(clientPartialKey);

            // If all partial keys are received
            if (isAgreementComplete()) {
                state = chatting;
                std::cout << "Agreement complete\n" << std::endl;
            }
        } else if (messageAuth.type == "ChatMSG" && state == chatting) {
            // If the other client is sending a chat message
            std::string message;
            readChatMessage(messageAuth, message);
        }
    }

    return 0;
}

int Client::readCertificate(AppMSG messageAuth, Certificate CACert, Certificate &newCert) {
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

int Client::sendPartialKey(void) {
    int nBytes;

    // Create partial key
    PartialKeyMSG baseMsg;
    baseMsg.generatePartialKey();
    this->sharedKey = baseMsg.partialKey;

    // Send partial key to each client
    for (ClientSession client : clients) {
        // Encrypt partial key for the destination client
        PartialKeyMSG clientMsg = baseMsg;
        clientMsg.encryptPartialKey(client.cert.publicKey);

        // Create authenticated integrity message
        AppMSG clientAuth(&clientMsg, cert.subjectName, client.cert.subjectName);
        clientAuth.sign(privateKey);

        nBytes = clientAuth.sendMSG(serverSocket);
        if (nBytes <= 0) {
            std::cerr << "Client partial key could not be sent" << std::endl;
            return 1;
        }
        std::cout << "Partial key sent to: " << client.cert.subjectName << std::endl;
    }

    return 0;
}

int Client::readPartialKey(AppMSG messageAuth, std::string &partialKey) {
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

    // Read in message and decrypt partial key
    PartialKeyMSG clientMsg;
    clientMsg.deserialize(messageAuth.msg);
    clientMsg.decryptPartialKey(privateKey);
    partialKey = clientMsg.partialKey;

    return 0;
}

int Client::sendChatMessage(std::string message) {
    int nBytes;

    // Create chat message and encrypt it with the shared key
    ChatMSG chat(cert.subjectName, message);
    chat.encryptMessage(this->sharedKey);

    // Create message without authenticated integrity check
    AppMSG clientAuth(&chat, std::string(), std::string());

    nBytes = clientAuth.sendMSG(serverSocket);
    if (nBytes <= 0) {
        std::cerr << "Client message could not be sent" << std::endl;
        return 1;
    }

    return 0;
}

int Client::readChatMessage(AppMSG messageAuth, std::string &message) {
    // Read in and decrypt message
    ChatMSG clientMsg;
    clientMsg.deserialize(messageAuth.msg);
    clientMsg.decryptMessage(this->sharedKey);
    message = clientMsg.message;

    std::cout << std::left << std::setw(10) << clientMsg.source << ": " << message << std::endl;

    return 0;
}

void Client::printClients(void) {
    system("cls");
    std::cout << this->cert.subjectName << "\n----------" << std::endl;
    std::cout << "\nClients" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    for (ClientSession client : clients) {
        std::cout << client.cert.subjectName << std::endl;
    }

    if (this->state == connected) {
        std::cout << std::endl << "Press 'y' to start a chat:" << std::endl;
    }
}

int Client::getClientSession(std::string subjectName, ClientSession **session) {
    for (ClientSession &client : clients) {
        if (client.cert.subjectName == subjectName) {
            *(session) = &client;
            return 0;
        }
    }

    return 1;
}


/* Private */


int Client::incorporatePartialKey(std::string clientPartialKey) {
    // Check if incoming partial key has the same length
    if (this->sharedKey.length() != clientPartialKey.length()) {
        std::cerr << "Input partial key is not the same length as the current partial key" << std::endl;
        return 1;
    }

    // Bitwise OR the current partial key with the incoming client partial key
    for (int i = 0; i < this->sharedKey.length(); i++) {
        this->sharedKey[i] |= clientPartialKey[i];
    }

    return 0;
}

bool Client::isAgreementComplete(void) {
    for (ClientSession &client : clients) {
        if (client.partialKey.empty()) {
            return false;
        }
    }
    return true;
}

bool Client::updateClients(Certificate clientCert) {
    bool exists = false;

    for (ClientSession client : clients) {
        if (client.cert.subjectName == clientCert.subjectName) {
            exists = true;
            break;
        }
    }

    if (exists == false) {
        ClientSession newSession(clientCert);
        clients.push_back(newSession);
    }

    return !exists;
}

int Client::setupServerSocket(char *serverIP, u_short port) {
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


int main(int argc, char* argv[]) {
    int err;

    // Certificates
    std::string stem = "certs/";
    stem.append(argv[1]);
    std::string privateString = stem + std::string("_private.der");
    std::string publicString  = stem + std::string("_public.der");
    const char *privateName   = privateString.c_str();
    const char *publicName    = publicString.c_str();

    // Read CA certificate
    Certificate CACert(publicCAName);

    // Create client object
    Client client(privateName, publicName);
    std::string logName = "logs/" + client.cert.subjectName + ".log";
    std::cout << client.cert.subjectName << "\n----------" << std::endl;

    err = client.start();
    if (err != 0) { return 1; }
    std::cout << "Client started" << std::endl;

    err = client.connectServer(serverIP, port, CACert);
    if (err != 0) { return 1; }
    std::cout << "Connected to server" << std::endl;

    // Listen for messages from server
    while (1) {
        // Check if there is data available on the socket
        u_long nAvailable;
        ioctlsocket(client.serverSocket, FIONREAD, &nAvailable);

        // Receive socket
        if (nAvailable > 0) {
            err = client.parseServerMessage(CACert);
            if (err != 0) { return 1; }
        }

        // Receive keyboard input
        if (_kbhit())  {
            std::string input;
            std::getline(std::cin, input);

            if (client.state == connected) {
                // If the user wants to connect
                if (input == "y") {
                    client.state = agreement;
                    // send nonce to other users through server
                    client.sendPartialKey();
                } else {
                    // Otherwise close the program
                    return 1;
                }
            }
            if (client.state == chatting && input != "") {
                client.sendChatMessage(input);
            }
        }
    }

    system("pause");
    return 0;
}
