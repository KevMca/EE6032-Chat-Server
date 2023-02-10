// Creates a private key and public key file
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include "cert.h"

int main(int argc, char* argv[])
{
    std::string subjectName = "Root";//"Alice";
    const char *privateName = "root_private.der";//"alice_private.der";
    const char *publicName  = "root_public.der";//"alice_public.der";
    const char *privateCAName = "root_private.der";
    const char *publicCAName  = "root_public.der";

    // Read CA private key and certificate
    /*CryptoPP::RSA::PrivateKey privateCAKey = Certificate::readPrivateKey(privateCAName);
    Certificate certCA(publicCAName);
    bool result = certCA.verify(certCA->publicKey);
    if (result == true) { std::cout << "Verified CA" << std::endl; } 
    else { std::cout << "Invalid CA" << std::endl; }*/
    
    // Generate certificate and keys
    Certificate cert(subjectName);
    CryptoPP::RSA::PrivateKey privateKey = cert.createKeys(2048);

    // Sign the certificate with CA's private key
    cert.sign(privateKey);

    //std::cout << "SubjectName: " << cert.subjectName << std::endl;
    //std::cout << "PrivateKey: " << cert.keyToString<CryptoPP::RSA::PrivateKey>(privateKey) << std::endl;
    //std::cout << "PublicKey: "  << cert.keyToString<CryptoPP::RSA::PublicKey>(cert.publicKey) << std::endl;
    //std::cout << "Signature: " << cert.signature << std::endl;

    // Save private key and public cert to files
    Certificate::saveKey<CryptoPP::RSA::PrivateKey>(privateKey, privateName);
    cert.save(publicName);

    /////////////////////////////////////////////////////////////

    // Read the certificate
    CryptoPP::RSA::PrivateKey privateKeyTest = Certificate::readKey<CryptoPP::RSA::PrivateKey>(privateName);
    Certificate certTest(publicName);

    // Verify private key is read correctly
    std::string privateKeyString     = Certificate::keyToString<CryptoPP::RSA::PrivateKey>(privateKey);
    std::string privateKeyTestString = Certificate::keyToString<CryptoPP::RSA::PrivateKey>(privateKeyTest);
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
    CryptoPP::RSA::PrivateKey privateKey2;
    privateKey2.GenerateRandomWithKeySize(rng, 2048);
    CryptoPP::RSA::PublicKey publicKey2(privateKey2);

    result = certTest.verify(publicKey2);
    if (result == false) { std::cout << "Verification test passed" << std::endl; } 
    else { std::cerr << "Verification test failed" << std::endl; }

    return 0;
}
