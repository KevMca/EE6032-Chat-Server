// https://stackoverflow.com/questions/12416175/loading-and-saving-vectors-to-a-file
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include "cert.h"
#include "encryption.h"

// Public

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

        this->publicKey = stringToPublicKey(publicKeyString);

        in.close();
    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }
}

template <typename T>
int Certificate::saveKey(T key, const char *fileName)
{
    using namespace CryptoPP;

    FileSink output(fileName);
    key.DEREncode(output);

    return 0;
}
template int Certificate::saveKey<CryptoPP::RSA::PublicKey>(CryptoPP::RSA::PublicKey key, const char *fileName);
template int Certificate::saveKey<CryptoPP::RSA::PrivateKey>(CryptoPP::RSA::PrivateKey key, const char *fileName);

template <typename T>
T Certificate::readKey(const char *fileName)
{
    using namespace CryptoPP;

    T key;

    FileSource input(fileName, true);
    key.BERDecode(input);

    return key;
}
template CryptoPP::RSA::PublicKey Certificate::readKey<CryptoPP::RSA::PublicKey>(const char *fileName);
template CryptoPP::RSA::PrivateKey Certificate::readKey<CryptoPP::RSA::PrivateKey>(const char *fileName);

int Certificate::printPrivateKey(CryptoPP::RSA::PrivateKey privateKey)
{
    using namespace CryptoPP;

    HexEncoder encoder(new CryptoPP::FileSink(std::cout));

    ByteQueue queue;
    privateKey.Save(queue);
    queue.TransferTo(encoder);
    std::cout << std::endl;

    return 0;
}

int Certificate::printPublicKey(CryptoPP::RSA::PublicKey publicKey)
{
    using namespace CryptoPP;

    HexEncoder encoder(new CryptoPP::FileSink(std::cout));

    ByteQueue queue;
    publicKey.Save(queue);
    queue.TransferTo(encoder);
    std::cout << std::endl;

    return 0;
}

int Certificate::save(const char *fileName)
{
    using namespace CryptoPP;
    std::ofstream out(fileName, std::ios::trunc);

    // Write subjectName
    this->writeString(out, subjectName);

    // Write publicKey
    std::string publicKeyString = this->keyToString<RSA::PublicKey>(this->publicKey);
    this->writeString(out, publicKeyString);

    // Write signature
    this->writeString(out, signature);

    out.close();

    return 0;
}

CryptoPP::RSA::PrivateKey Certificate::createKeys(unsigned int keySize)
{
    using namespace CryptoPP;

    AutoSeededRandomPool rng;

    RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, keySize);
    RSA::PublicKey pKey(privateKey);
    this->publicKey = pKey;

    return privateKey;
}

int Certificate::sign(CryptoPP::RSA::PrivateKey privateCAKey)
{
    using namespace CryptoPP;

    // Convert contents to string
    std::string contents = this->contentsToString();

    // Sign the contents
    std::string signature;
    Encryption::sign(contents, signature, privateCAKey);

    // Remove the start from the signature
    signature.erase(0, contents.length());

    // Convert to hex
    StringSource ss(signature, true,
        new HexEncoder( new StringSink(this->signature) )
    );

    return 0;
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

    std::string sig = contents;
    sig.insert( sig.end(), sigString.begin(), sigString.end() );

    // Verify the contents
    std::string recovered;
    bool result = Encryption::verify(sig, recovered, publicCAKey);
    
    return result;
}

// Private

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
template std::string Certificate::keyToString<CryptoPP::RSA::PublicKey>(CryptoPP::RSA::PublicKey key);
template std::string Certificate::keyToString<CryptoPP::RSA::PrivateKey>(CryptoPP::RSA::PrivateKey key);

CryptoPP::RSA::PublicKey Certificate::stringToPublicKey(std::string publicKeyString)
{
    using namespace CryptoPP;

    // Decode string
    std::string publicKeyDecoded;
    HexDecoder decoder(new StringSink(publicKeyDecoded));
    decoder.Put( (byte*)publicKeyString.data(), publicKeyString.size() );
    decoder.MessageEnd();

    RSA::PublicKey publicKey;
    StringSource stringSource(publicKeyDecoded, true);
    publicKey.BERDecode(stringSource);

    return publicKey;
}

std::string Certificate::contentsToString(void)
{
    using namespace CryptoPP;

    // Convert public key to string
    std::string publicKeyString = this->keyToString<RSA::PublicKey>(this->publicKey);

    // Concatenate subjectName and publicKeyString
    std::string out(subjectName.begin(), subjectName.end());
    out.insert( out.end(), publicKeyString.begin(), publicKeyString.end() );

    return out;
}
