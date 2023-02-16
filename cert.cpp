// Source file for creating certificates and manipulating their keys
//
// Sources:
// https://stackoverflow.com/questions/12416175/loading-and-saving-vectors-to-a-file

// Cryptography includes
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>

// Local includes
#include "cert.h"
#include "encryption.h"

/* Constructors */


Certificate::Certificate()
{
    
}

Certificate::Certificate(std::string subjectName)
{
    this->subjectName = subjectName;
}

Certificate::Certificate(const char *fileName)
{
    using namespace CryptoPP;

    try
    {
        std::string publicKeyString;
        std::ifstream in(fileName);

        this->readString(in, this->subjectName);
        this->readString(in, publicKeyString);
        this->readString(in, this->signature);

        this->publicKey = stringToKey<RSA::PublicKey>(publicKeyString);

        in.close();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}


/* Instance functions */


void Certificate::save(const char *fileName)
{
    using namespace CryptoPP;

    try
    {
        std::ofstream out(fileName, std::ios::trunc);
        std::string publicKeyString = this->keyToString<RSA::PublicKey>(this->publicKey);

        this->writeString(out, subjectName);
        this->writeString(out, publicKeyString);
        this->writeString(out, signature);

        out.close();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

CryptoPP::RSA::PrivateKey Certificate::createKeys(unsigned int keySize)
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);

    RSA::PublicKey publicKey(privateKey);
    this->publicKey = publicKey;

    return privateKey;
}

void Certificate::sign(CryptoPP::RSA::PrivateKey privateCAKey)
{
    using namespace CryptoPP;

    // Convert contents to string
    std::string contents = this->contentsToString();

    // Sign the contents
    std::string signature;
    Encryption::sign(contents, signature, privateCAKey);

    // Remove contents from the signature
    signature.erase(0, contents.length());

    // Convert to hex
    StringSource ss(signature, true,
        new HexEncoder( new StringSink(this->signature) )
    );
}

bool Certificate::verify(CryptoPP::RSA::PublicKey publicCAKey)
{
    using namespace CryptoPP;

    // Convert contents to string and add back to the signature
    std::string contents = this->contentsToString();

    // Convert from hex
    std::string sigString;
    StringSource ss(this->signature, true,
        new HexDecoder( new StringSink(sigString) )
    );

    // Append signature to contents
    std::string sig = contents;
    sig.insert( sig.end(), sigString.begin(), sigString.end() );

    // Verify the signature and contents
    std::string recovered;
    bool result = Encryption::verify(sig, recovered, publicCAKey);
    
    return result;
}

std::string Certificate::toString(void)
{
    using namespace CryptoPP;

    // Convert subject name and public key to string
    std::string contents = this->contentsToString();

    // Append signature string
    std::string certString = contents;
    certString.insert( certString.end(), signature.begin(), signature.end() );
    
    return certString;
}


/* Static key functions */


template <typename T>
void Certificate::saveKey(T key, const char *fileName)
{
    using namespace CryptoPP;

    try
    {
        FileSink output(fileName);
        key.DEREncode(output);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

template <typename T>
T Certificate::readKey(const char *fileName)
{
    using namespace CryptoPP;

    T key;

    try
    {
        FileSource input(fileName, true);
        key.BERDecode(input);
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return key;
}

template <typename T>
std::string Certificate::keyToString(T key)
{
    using namespace CryptoPP;

    std::string keyString;
    HexEncoder encoder(new StringSink(keyString));

    ByteQueue keyBytes;
    key.DEREncode(keyBytes);
    keyBytes.TransferTo(encoder);

    return keyString;
}

template <typename T>
T Certificate::stringToKey(std::string keyString)
{
    using namespace CryptoPP;

    std::string keyDecoded;
    T key;

    HexDecoder decoder(new StringSink(keyDecoded));
    decoder.Put( (byte*)keyString.data(), keyString.size() );
    decoder.MessageEnd();

    StringSource ss(keyDecoded, true);
    key.BERDecode(ss);

    return key;
}

template <typename T>
void Certificate::printKey(T key)
{
    std::string keyString = keyToString<T>(key);
    std::cout << keyString << std::endl;
}


/* Private */


void Certificate::writeString(std::ostream &out, const std::string &data)
{
    unsigned int len = data.size();
    out.write( (char*)&len, sizeof(len) );
    out.write( (const char*)&data[0], len * sizeof(data[0]) );
}

void Certificate::readString(std::istream &in, std::string &data)
{
    unsigned int len = 0;
    in.read( (char*)&len, sizeof(len) );
    data.resize(len);
    if( len > 0 )
    {
        in.read( (char*)&data[0], len * sizeof(data[0]) );
    }
}

std::string Certificate::contentsToString(void)
{
    using namespace CryptoPP;

    std::string publicKeyString = this->keyToString<RSA::PublicKey>(this->publicKey);

    // Concatenate subjectName and publicKeyString
    std::string out(subjectName.begin(), subjectName.end());
    out.insert( out.end(), publicKeyString.begin(), publicKeyString.end() );

    return out;
}


/* Templates */


template void Certificate::saveKey<CryptoPP::RSA::PublicKey>(CryptoPP::RSA::PublicKey key, const char *fileName);
template void Certificate::saveKey<CryptoPP::RSA::PrivateKey>(CryptoPP::RSA::PrivateKey key, const char *fileName);
template CryptoPP::RSA::PublicKey Certificate::readKey<CryptoPP::RSA::PublicKey>(const char *fileName);
template CryptoPP::RSA::PrivateKey Certificate::readKey<CryptoPP::RSA::PrivateKey>(const char *fileName);
template std::string Certificate::keyToString<CryptoPP::RSA::PublicKey>(CryptoPP::RSA::PublicKey key);
template std::string Certificate::keyToString<CryptoPP::RSA::PrivateKey>(CryptoPP::RSA::PrivateKey key);
template CryptoPP::RSA::PublicKey Certificate::stringToKey<CryptoPP::RSA::PublicKey>(std::string keyString);
template CryptoPP::RSA::PrivateKey Certificate::stringToKey<CryptoPP::RSA::PrivateKey>(std::string keyString);
template void Certificate::printKey<CryptoPP::RSA::PublicKey>(CryptoPP::RSA::PublicKey key);
template void Certificate::printKey<CryptoPP::RSA::PrivateKey>(CryptoPP::RSA::PrivateKey key);
