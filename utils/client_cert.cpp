// Creates a new client certificate and private key file pair that is signed by a CA certificate

// Cryptography includes
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>

// Local includes
#include "../cert.h"

int main(int argc, char* argv[])
{
    std::string subjectName = "Carol";
    const char *privateName = "certs/carol_private.der";
    const char *publicName  = "certs/carol_public.der";
    const char *privateCAName = "certs/root_private.der";
    const char *publicCAName  = "certs/root_public.der";

    typedef CryptoPP::RSA::PrivateKey PrivateKey;
    typedef CryptoPP::RSA::PublicKey  PublicKey;

    // Read CA certificate and key
    PrivateKey privateCAKey = Certificate::readKey<PrivateKey>(privateCAName);
    Certificate certCA(publicCAName);
    
    // Generate certificate and keys signed by CA
    Certificate cert(subjectName);
    PrivateKey privateKey = cert.createKeys(2048);
    cert.sign(privateCAKey);

    // Save private key and public cert to files
    cert.saveKey<PrivateKey>(privateKey, privateName);
    cert.save(publicName);

    /////////////////////////////////////////////////////////////

    // Read the certificate
    PrivateKey privateKeyTest = Certificate::readKey<PrivateKey>(privateName);
    Certificate certTest(publicName);

    // Verify private key is read correctly
    std::string privateKeyString     = Certificate::keyToString<PrivateKey>(privateKey);
    std::string privateKeyTestString = Certificate::keyToString<PrivateKey>(privateKeyTest);
    if (privateKeyString == privateKeyTestString) { std::cout << "Private key read correctly" << std::endl; } 
    else { std::cerr << "Private key read incorrectly" << std::endl; }

    // Verify certificate with CA certificate
    bool result = certTest.verify(certCA.publicKey);
    if (result == true) { std::cout << "Signature matches certificate" << std::endl; } 
    else 
    { 
        if (cert.signature != certTest.signature)
        { 
            std::cerr << "Signature does not match certificate: " << std::endl; 
            std::cerr << cert.signature << std::endl;
            std::cerr << certTest.signature << std::endl;
        }
        else { std::cerr << "CA public key does not match certificate" << std::endl; }
    }

    // Test verification works with random key

    CryptoPP::AutoSeededRandomPool rng;
    PrivateKey privateKey2;
    privateKey2.GenerateRandomWithKeySize(rng, 2048);
    PublicKey publicKey2(privateKey2);

    result = certTest.verify(publicKey2);
    if (result == false) { std::cout << "Verification test passed" << std::endl; } 
    else { std::cerr << "Verification test failed" << std::endl; }

    return 0;
}
