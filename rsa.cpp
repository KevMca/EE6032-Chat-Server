// Simple example of AES CBC encryption using crypto++ library
//
// Sources:
// https://www.cryptopp.com/wiki/RSA_Cryptography
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>

int encrypt(std::string &plain, std::string &cipher, CryptoPP::RSA::PublicKey publicKey, CryptoPP::AutoSeededRandomPool &rng)
{
    using namespace CryptoPP;

    RSAES_OAEP_SHA_Encryptor e(publicKey);

    // Create encryption pipeline to pipe plaintext to cipher
    // rng is needed for padding operations
    StringSource ss1(plain, true,
        new PK_EncryptorFilter(rng, e, new StringSink(cipher))
    );

    return 0;
}

int decrypt(std::string &cipher, std::string &recovered, CryptoPP::RSA::PrivateKey privateKey, CryptoPP::AutoSeededRandomPool &rng)
{
    using namespace CryptoPP;

    RSAES_OAEP_SHA_Decryptor d(privateKey);

    // Create decryption pipeline to pipe ciphertext to recovered plaintext
    StringSource ss2(cipher, true,
        new PK_DecryptorFilter(rng, d, new StringSink(recovered))
    );

    return 0;
}

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    InvertibleRSAFunction params;
    HexEncoder encoder(new FileSink(std::cout));
    unsigned int keySize = 3072;
    std::string plain="RSA Encryption", cipher, recovered;
    
    // Generate keys
    params.GenerateRandomWithKeySize(rng, keySize);
    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    // Encrypt and decrypt message
    encrypt(plain, cipher, publicKey, rng);
    decrypt(cipher, recovered, privateKey, rng);

    // Output recovered text
    std::cout << "Recovered plain text: " << recovered << std::endl;

    system("pause");
    return 0;
}