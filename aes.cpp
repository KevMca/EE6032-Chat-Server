// Simple example of AES CBC encryption using crypto++ library
//
// Sources:
// https://www.cryptopp.com/wiki/Advanced_Encryption_Standard
#include <cryptopp/cryptlib.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>

#include <iostream>
#include <string>

int encrypt(std::string &plain, std::string &cipher, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv)
{
    using namespace CryptoPP;

    try
    {
        // Setup encryption type to use AES in Cipher Block Chaining (CBC) mode
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        // Create encryption pipeline to pipe plaintext to cipher
        StringSource s(plain, true,
            new StreamTransformationFilter(e, new StringSink(cipher))
        );
    }
    catch(const Exception& err)
    {
        std::cerr << err.what() << std::endl;
        exit(1);
    }

    return 0;
}

int decrypt(std::string &cipher, std::string &recovered, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv)
{
    using namespace CryptoPP;

    try
    {
        // Setup decryption type to use AES in Cipher Block Chaining (CBC) mode
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        // Create decryption pipeline to pipe ciphertext to recovered plaintext
        StringSource s(cipher, true, 
            new StreamTransformationFilter(d, new StringSink(recovered))
        );
    }
    catch(const Exception& e)
    {
        std::cerr << e.what() << std::endl;
        exit(1);
    }

    return 0;
}

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    // Create random number generator for generating key and iv
    AutoSeededRandomPool prng;
    HexEncoder encoder(new FileSink(std::cout));

    // SecBlock is used to provide secure storage that is zeroized when block is destroyed
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);       // key
    SecByteBlock iv(AES::BLOCKSIZE);                // initial variation

    // Create plaintext, ciphertext and recovered text variables
    std::string plain = "CBC Mode Test";            // plaintext
    std::string cipher, recovered;                  // cipher, recovered

    // Generate random key and iv
    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    // Encrypt and decrypt message
    encrypt(plain, cipher, key, iv);
    decrypt(cipher, recovered, key, iv);

    // Output plaintext, key, iv, ciphertext and recovered text
    std::cout << "plain text: " << plain << std::endl;

    std::cout << "key: ";
    encoder.Put(key, key.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "iv: ";
    encoder.Put(iv, iv.size());
    encoder.MessageEnd();
    std::cout << std::endl;

    std::cout << "cipher text: ";
    encoder.Put((const byte*)&cipher[0], cipher.size());
    encoder.MessageEnd();
    std::cout << std::endl;
    std::cout << "recovered text: " << recovered << std::endl;

    system("pause");
    return 0;
}