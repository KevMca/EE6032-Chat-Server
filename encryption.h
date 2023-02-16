
#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/filters.h>

#include <cassert>

class Encryption {
    public:
        static std::string generateNonce(size_t size = 16);
        static void encrypt(std::string &plain, std::string &cipher, CryptoPP::RSA::PublicKey publicKey);
        static void decrypt(std::string &cipher, std::string &recovered, CryptoPP::RSA::PrivateKey privateKey);
        static int sign(std::string &plain, std::string &signature, CryptoPP::RSA::PrivateKey privateKey);
        static bool verify(std::string &signature, std::string &recovered, CryptoPP::RSA::PublicKey publicKey);
};

#endif
