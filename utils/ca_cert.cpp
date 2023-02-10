// Creates a new self-signed CA certificate and private key file pair
//
// Sources:
//

// Cryptography includes
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>

// Local includes
#include "../cert.h"

int main(int argc, char* argv[])
{
    std::string subjectName = "Root";
    const char *privateName = "certs/root_private.der";
    const char *publicName  = "certs/root_public.der";

    typedef CryptoPP::RSA::PrivateKey PrivateKey;
    typedef CryptoPP::RSA::PublicKey  PublicKey;
    
    // Generate self-signed certificate and keys
    Certificate cert(subjectName);
    PrivateKey privateKey = cert.createKeys(2048);
    cert.sign(privateKey);

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
    bool result = certTest.verify(certTest.publicKey);
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
