// Sources:
// https://stackoverflow.com/questions/7046244/serializing-a-class-which-contains-a-stdstring

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
// basic functions like serialization and sending over sockets
class SockMSG 
{
    public:
        // Send a message object over a specific socket
        // Inputs -> socket: the socket to use to send the data
        // Returns -> the number of bytes sent
        virtual int sendMSG(SOCKET socket);

        // Read a message object over a specific socket
        // Inputs -> socket: the socket to use to read the data
        // Returns -> the number of bytes read
        virtual int readMSG(SOCKET socket);

        // Converts the contents of a message into a hex string. This function must be implemented
        // in each derived class of this base class.
        // Returns -> the serialized contents of the message
        virtual std::string serialize(void) = 0;

        // Converts the serialized contents of the message into a message object. This function
        // must be implemented in each derived class of this base class.
        // Inputs -> str: the serialized contents of the message
        virtual void deserialize(std::string str) = 0;

        // A standard way to convert a std::string to a hex string which can be easily sent over a
        // network
        // Inputs -> out: the stringstream object used to compile strings
        //           data: the data to serialize
        void serializeString(std::ostream &out, std::string data);

        // A standard way to convert a serialized string to a std::string object
        // Inputs -> in: the stringstream object used to compile strings
        //           data: the data that contains information about a std::string
        void deserializeString(std::istream &in, std::string &data);
};

// Represents a socket message including a certificate and a nonce, used for verification and 
// freshness. The nonce can be optionally encrypted if the recipient's cert is known
// Notation: {CA<<A>>, N}
// Sending Example:
//      CertMSG clientCertMsg(cert);
// Receiving Example:
//      CertMSG clientCertMsg;
//      clientCertMsg.deserialize(socketMsg)
class CertMSG: public SockMSG
{
    public:
        Certificate cert;
        std::string nonce;
        bool encrypted = NULL; // (Not encrypted: false, Encrypted: true, Unknown: NULL)

        explicit CertMSG();

        // Constructs a CertMSG from a Certificate object
        explicit CertMSG(Certificate cert);

        // Converts the contents of the certificate and nonce into a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into a CertMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);

        // Encrypts the nonce so only the recipient can access it
        // Inputs -> publicKey: the public key of the recipient
        void encryptNonce(CryptoPP::RSA::PublicKey publicKey);

        // Decrypts the nonce so the intended recipient can access it
        // Inputs -> privateKey: the private key of the recipient
        void decryptNonce(CryptoPP::RSA::PrivateKey privateKey);
};

// Represents a message with an authenticated integrity check
// Notation: {msg, {H(msg)}_k^-1}
// Sending Example:
//      AuthMSG clientCertMsgAuth(&clientCertMsg, privateKey);
// Receiving Example:
//      AuthMSG serverCertMsgAuth;
//      nBytes = serverCertMsgAuth.readMSG(serverSocket);
//      isVerified = serverCertMsgAuth.verify(cert.publicKey);
class AuthMSG: public SockMSG
{
    public:
        std::string msg;
        std::string signature;

        explicit AuthMSG();

        // Constructs an AuthMSG object from a SockMSG derived object
        // Inputs -> msg: a pointer to a SockMSG derived object
        //           privateKey: the private key used to sign the message
        explicit AuthMSG(SockMSG *msg, CryptoPP::RSA::PrivateKey privateKey);

        // Constructs an AuthMSG object from a string
        // Inputs -> msg: the hex string of a message to sign
        //           privateKey: the private key used to sign the message
        explicit AuthMSG(std::string msg, CryptoPP::RSA::PrivateKey privateKey);

        // Converts the contents of the message and signature into a hex string
        // Returns -> the serialized contents of the message
        std::string serialize(void);

        // Converts the serialized contents of the string into an AuthMSG object
        // Inputs -> str: the serialized contents of the message
        void deserialize(std::string str);

        // Verifies if the signature of an AuthMSG matches the message
        // Inputs -> publicKey: the public key of the sender
        // Returns -> if the signature matches the message
        bool verify(CryptoPP::RSA::PublicKey publicKey);

        // Creates a signature from a message
        // Inputs -> privateKey: the private key of the sender
        // Returns -> the signature of the message
        std::string createSignature(CryptoPP::RSA::PrivateKey privateKey);
};
