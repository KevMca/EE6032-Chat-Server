// Copyright 2023 Kevin McAndrew
// Encryption header file for encapsulating cryptopp encryption and vertification functions
//
// Sources:
//

#ifndef ENCRYPTION_H_
#define ENCRYPTION_H_

#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/filters.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/modes.h>

#include <cassert>
#include <string>

class Encryption {
 public:
    // Generates a random partial key
    // Inputs -> size: size of partial key in bytes
    // Returns -> the partial key as a string
    static std::string generatePartialKey(size_t size = 16);

    // Encrypts some plaintext using AES in CBC mode
    // Inputs -> plain: the plaintext to encrypt
    //           sharedKey: the symmetric key to use to encrypt
    //           iv: the initial variation used to initial the CBC buffer
    // Outputs -> cipher: the output ciphertext
    // Returns -> 0 if there are no errors, 1 if there is an encryption error
    static int symEncrypt(std::string plain, std::string &cipher, std::string sharedKey, CryptoPP::SecByteBlock iv);

    // Decrypts some ciphertext using AES in CBC mode
    // Inputs -> cipher: the incoming ciphertext to decrypt
    //           sharedKey: the symmetric key to use to encrypt
    //           iv: the initial variation used to initial the CBC buffer
    // Outputs -> recovered: the output recovered plaintext
    // Returns -> 0 if there are no errors, 1 if there is an encryption error
    static int symDecrypt(std::string cipher, std::string &recovered, std::string sharedKey, CryptoPP::SecByteBlock iv);

    // Encrypts some plaintext using RSAES_OAEP_SHA
    // Inputs -> plain: the plaintext to encrypt
    //           publicKey: the public key of the recipient
    // Outputs -> cipher: the output ciphertext
    static void asymEncrypt(std::string plain, std::string &cipher, CryptoPP::RSA::PublicKey publicKey);

    // Decrypts some ciphertext using RSAES_OAEP_SHA
    // Inputs -> cipher: the incoming ciphertext to decrypt
    //           publicKey: the public key of the recipient
    // Outputs -> recovered: the output recovered plaintext
    static void asymDecrypt(std::string cipher, std::string &recovered, CryptoPP::RSA::PrivateKey privateKey);

    // Creates a signature of some plaintext using RSASS<PSS, SHA256>
    // Inputs -> plain: the plaintext to sign
    //           privateKey: the private key of the entity that is signing
    // Outputs -> signature: the plaintext with appended signature
    // Returns -> 0 if there are no errors, 1 if there was an error
    static int sign(std::string plain, std::string &signature, CryptoPP::RSA::PrivateKey privateKey);

    // Verifies a signature using RSASS<PSS, SHA256>
    // Inputs -> signature: the plaintext with appended signature
    //           publicKey: the public key of the entity that created the signature
    // Outputs -> recovered: the output recovered plaintext
    // Returns -> true if the signature matches the plaintext with the given key
    static bool verify(std::string signature, std::string &recovered, CryptoPP::RSA::PublicKey publicKey);
};

#endif  // ENCRYPTION_H_
