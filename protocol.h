// Sources:
// https://stackoverflow.com/questions/7046244/serializing-a-class-which-contains-a-stdstring

#include <iostream>
#include <ostream>
#include <istream>
#include <vector>
#include <sstream>
#include <cassert>

#include <cryptopp/osrng.h>

#include "cert.h"
#include "encryption.h"

#define DEFAULT_BUFLEN 2048

class SockMSG 
{
    public:
        void SockMSG::serializeString(std::ostream &out, std::string data);
        void SockMSG::deserializeString(std::istream &in, std::string &data);
};

// Represents a socket message including a certificate and a nonce, used for verification and 
// freshness. The nonce can be optionally encrypted if the recipient's cert is known
// Notation: {CA<<A>>, {N}_kS} ... {CA<<A>>, N}
// Sending Example:
//      CertMSG clientCertMsg(clientCert, recipientMsg);
//      std::string socketMsg = clientCertMsg.serialize()
// Receiving Example:
//      CertMSG clientCertMsg;
//      clientCertMsg.deserialize(socketMsg)
//      clientCertMsg.decryptNonce(privateKey)
class CertMSG: private SockMSG
{
    public:
        Certificate cert;
        std::string nonce;
        bool encrypted = NULL;

        explicit CertMSG();
        explicit CertMSG(Certificate cert);
        std::string serialize(void);
        void deserialize(std::string str);
        void encryptNonce(CryptoPP::RSA::PublicKey publicKey);
        void decryptNonce(CryptoPP::RSA::PrivateKey privateKey);
};

class AuthMSG: private SockMSG
{
    public:
        std::string data;
        std::string signature;

        AuthMSG();
        AuthMSG(std::string data, std::string signature);
        std::string serialize(void);
        void deserialize(std::string str);
        bool verify(void);
};
