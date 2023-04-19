// Sources:
// https://stackoverflow.com/questions/7046244/serializing-a-class-which-contains-a-stdstring

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <iostream>
#include <ostream>
#include <istream>
#include <vector>
#include <sstream>
#include <cassert>

#include <cryptopp/osrng.h>

// Include socket libraries
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

#include "cert.h"
#include "encryption.h"

#define DEFAULT_BUFLEN 4096

// A base abstract class for all messages to be sent in the protocol. Each message requires some
// basic functions for serialization and communication over sockets
class BaseMSG 
{
    public:
        // Serialize the current message and send it over a specific socket
        // Inputs -> socket: the socket to use to send the data
        // Returns -> the number of bytes sent
        int sendMSG(SOCKET socket);

        // Read a message object over a specific socket and deserialize the socket message
        // Inputs -> socket: the socket to use to read the data
        // Returns -> the number of bytes read
        int readMSG(SOCKET socket);

        // A standard way to convert a std::string to a hex string which can be easily sent over a
        // network
        // Inputs -> out: the stringstream object used to compile strings
        //           data: the data to serialize
        void serializeString(std::ostream &out, std::string data);

        // A standard way to convert a serialized string to a std::string object
        // Inputs -> in: the stringstream object used to compile strings
        //           data: the data that contains information about a std::string
        void deserializeString(std::istream &in, std::string &data);

        /* Virtual functions to be implemented with each message */

        // Converts the contents of a message into a hex string. This function must be implemented
        // in each derived class of this base class.
        // Returns -> the serialized contents of the message
        virtual std::string serialize(void) = 0;

        // Converts the serialized contents of the message into a message object. This function
        // must be implemented in each derived class of this base class.
        // Inputs -> str: the serialized contents of the message
        virtual void deserialize(std::string str) = 0;
};

// A message containing a certificate
// Notation: CA<<A>>
// Sending Example:
//      CertMSG clientCertMsg(cert);
// Receiving Example:
//      CertMSG clientCertMsg;
//      clientCertMsg.deserialize(socketMsg)
class CertMSG: public BaseMSG
{
    public:
        Certificate cert;

        // Empty CertMSG constructor which does not generate a nonce
        explicit CertMSG();

        // Constructs a CertMSG from a Certificate object and generates a nonce
        explicit CertMSG(Certificate cert);

        // Converts the contents of the certificate and nonce into a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into a CertMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);
};

// Represents a socket message with a challenge nonce and a response nonce. The nonces can be
// encrypted if the recipient's cert is known
// Notation: {Nc, Nr}_K_A^-1
// Sending Example:
//      ChallengeMSG challengeMsg(response);
// Receiving Example:
//      ChallengeMSG challengeMsg;
//      challengeMsg.deserialize(socketMsg);
class ChallengeMSG: public BaseMSG
{
    public:
        std::string challenge = "";
        std::string response = "";
        bool encrypted = NULL; // (Not encrypted: false, Encrypted: true, Unknown: NULL)

        // Empty ChallengeMSG constructor
        explicit ChallengeMSG();

        // Constructs a ChallengeMSG with a response
        explicit ChallengeMSG(std::string response);

        // Converts the challenge and response to a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into a ChallengeMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);

        // Generates a random challenge nonce
        std::string generateChallenge(void);

        // Encrypts the nonces so only the recipient can access it
        // Inputs -> publicKey: the public key of the recipient
        void encryptNonces(CryptoPP::RSA::PublicKey publicKey);

        // Decrypts the nonces so the intended recipient can access it
        // Inputs -> privateKey: the private key of the recipient
        void decryptNonces(CryptoPP::RSA::PrivateKey privateKey);
};

// Represents a socket message with a nonce used for key agreement
// Notation: {K_a}K_B
class PartialKeyMSG: public BaseMSG
{
    public:
        std::string partialKey;
        bool encrypted = NULL; // (Not encrypted: false, Encrypted: true, Unknown: NULL)

        // Empty PartialKeyMSG constructor
        explicit PartialKeyMSG();

        // Converts the nonce to a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into a PartialKeyMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);

        // Generates a random challenge nonce
        void generatePartialKey(void);

        // Encrypts the partial key so only the intended recipient can access it
        // Inputs -> publicKey: the public key of the recipient
        void encryptPartialKey(CryptoPP::RSA::PublicKey publicKey);

        // Decrypts the partial key so only the intended recipient can access it
        // Inputs -> privateKey: the private key of the recipient
        void decryptPartialKey(CryptoPP::RSA::PrivateKey privateKey);
};

// Represents a socket message with an encrypted chat message and the IV used to encrypt the
// message
// Notation: {Msg}K_abc, IV
class ChatMSG: public BaseMSG
{
    public:
        std::string source;           // source
        std::string message;          // msg
        std::string encryptedMessage; // {source, msg}_k_abc
        CryptoPP::SecByteBlock iv;
        bool encrypted = NULL; // (Not encrypted: false, Encrypted: true, Unknown: NULL)

        // Empty ChatMSG constructor
        explicit ChatMSG();

        // Constructs a ChatMSG with a source and message
        explicit ChatMSG(std::string source, std::string message);

        // Converts the chat message to a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into a ChatMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);

        // Symmetrically encrypts the chat message so only the recipient can access it
        // Inputs -> sharedKey: the shared key that is known by all parties
        void encryptMessage(std::string sharedKey);

        // Symmetrically decrypts the chat message so the intended recipient can access it
        // Inputs -> sharedKey: the shared key that is known by all parties
        void decryptMessage(std::string sharedKey);
};

// A generic message wrapper for sending messages within the chat server application. It gives the
// option for authenticated integrity, type information and source and destination information
// Notation: {type, source, destination, msg, {H(msg)}_K_A^-1}
// Sending Example:
//      AppMSG clientCertMsgAuth(&clientCertMsg, privateKey);
// Receiving Example:
//      AppMSG serverCertMsgAuth;
//      nBytes = serverCertMsgAuth.read(serverSocket);
//      isVerified = serverCertMsgAuth.verify(cert.publicKey);
class AppMSG: public BaseMSG
{
    public:
        std::string type;
        std::string source;
        std::string destination;
        std::string msg;
        std::string signature;

        explicit AppMSG();

        // Constructs an AppMSG object from a BaseMSG derived object without digital signature
        // Inputs -> msg: a pointer to a BaseMSG derived object
        //           source: the name of the source entity
        //           destination: the name of the destination entity
        explicit AppMSG(BaseMSG *msg, std::string source, std::string destination);

        // Constructs an AppMSG object from a string without digital signature
        // Inputs -> msg: the hex string of a message to sign
        //           source: the name of the source entity
        //           destination: the name of the destination entity
        explicit AppMSG(std::string msg, std::string source, std::string destination);
        
        // Converts the contents of the message and signature into a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into an AppMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);

        // Verifies if the signature of an AppMSG matches the message
        // Inputs -> publicKey: the public key of the sender
        // Returns -> if the signature matches the message
        bool verify(CryptoPP::RSA::PublicKey publicKey);

        // Creates a signature from a message
        // Inputs -> privateKey: the private key of the sender
        // Outputs -> the hashed signature of the message
        void sign(CryptoPP::RSA::PrivateKey privateKey);
};

#endif
