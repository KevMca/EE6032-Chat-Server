#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/filters.h>
#include "encryption.h"

std::string Encryption::generateNonce(size_t size)
{
    using namespace CryptoPP;

    SecByteBlock nonce(size);
    AutoSeededRandomPool prng;

    prng.GenerateBlock(nonce, nonce.size());

    std::string nonceString(reinterpret_cast<const char*>(&nonce[0]), nonce.size());
    return nonceString;
}

void Encryption::encrypt(std::string &plain, std::string &cipher, CryptoPP::RSA::PublicKey publicKey)
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Encryptor e(publicKey);

    // Create encryption pipeline to pipe plaintext to cipher
    StringSource ss1(plain, true,
        new PK_EncryptorFilter(rng, e, new StringSink(cipher))
    );
}

void Encryption::decrypt(std::string &cipher, std::string &recovered, CryptoPP::RSA::PrivateKey privateKey)
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA_Decryptor d(privateKey);

    // Create decryption pipeline to pipe ciphertext to recovered plaintext
    StringSource ss2(cipher, true,
        new PK_DecryptorFilter(rng, d, new StringSink(recovered))
    );
}

int Encryption::sign(std::string &plain, std::string &signature, CryptoPP::RSA::PrivateKey privateKey)
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    // Sign and Encode
    RSASS<PSS, SHA256>::Signer signer(privateKey);

    StringSource ss1(plain, true, 
        new SignerFilter(rng, signer,
            new StringSink(signature), true
        )
    );

    return 0;
}

bool Encryption::verify(std::string &signature, std::string &recovered, CryptoPP::RSA::PublicKey publicKey)
{
    using namespace CryptoPP;

    // Verify if the digest of plaintext is the same as the decrypted signature
    RSASS<PSS, SHA256>::Verifier verifier(publicKey);

    bool result = true;

    try
    {
        StringSource ss2(signature, true,
            new SignatureVerificationFilter(verifier,
                new StringSink(recovered), HashVerificationFilter::PUT_MESSAGE | HashVerificationFilter::THROW_EXCEPTION
            )
        );
    } 
    catch (...)
    {
        result = false;
    }

    return result;
}
