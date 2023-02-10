#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>

class Encryption {
    public:
        static int encrypt(std::string &plain, std::string &cipher, CryptoPP::RSA::PublicKey publicKey);
        static int decrypt(std::string &cipher, std::string &recovered, CryptoPP::RSA::PrivateKey privateKey);
        static int sign(std::string &plain, std::string &signature, CryptoPP::RSA::PrivateKey privateKey);
        static bool verify(std::string &signature, std::string &recovered, CryptoPP::RSA::PublicKey publicKey);
};