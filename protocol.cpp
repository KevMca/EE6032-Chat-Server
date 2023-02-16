
#include "protocol.h"

void SockMSG::serializeString(std::ostream &out, std::string data)
{
    out << data.size();
    out << ',';
    out << data;
    out << ',';
}

void SockMSG::deserializeString(std::istream &in, std::string &data)
{
    int len = 0;
    char comma;
    in >> len;
    in >> comma;
    if (in && len) {
        std::vector<char> tmp(len);
        in.read(tmp.data(), len);
        data.assign(tmp.data(), len);
    }
    in >> comma;
}

CertMSG::CertMSG()
{

}

CertMSG::CertMSG(Certificate cert)
{
    this->cert = cert;
    this->nonce = Encryption::generateNonce();
    encrypted = false;
}

std::string CertMSG::serialize(void)
{
    std::stringstream out;
    std::string str;
    std::string nonceString;

    CryptoPP::StringSource ss2(nonce, true, 
        new CryptoPP::HexEncoder( new CryptoPP::StringSink(nonceString) )
    );
    
    // Serialize certificate
    serializeString(out, cert.subjectName);
    serializeString(out, cert.keyToString(cert.publicKey));
    serializeString(out, cert.signature);
    serializeString(out, nonceString);

    str = out.str();

    return str;
}

void CertMSG::deserialize(std::string str)
{
    std::stringstream in;
    in.str(str);

    Certificate cert;
    std::string subjectName;
    std::string publicKeyString;
    std::string signature;    
    std::string nonceCipher;

    deserializeString(in, subjectName);
    deserializeString(in, publicKeyString);
    deserializeString(in, signature);
    deserializeString(in, nonceCipher);

    cert.subjectName = subjectName;
    cert.publicKey = cert.stringToKey<CryptoPP::RSA::PublicKey>(publicKeyString);
    cert.signature = signature;
    this->cert = cert;

    CryptoPP::StringSource ss1(nonceCipher, true, 
        new CryptoPP::HexDecoder( new CryptoPP::StringSink(this->nonce) )
    );
}

void CertMSG::encryptNonce(CryptoPP::RSA::PublicKey publicKey)
{
    std::string cipher;
    Encryption::encrypt(nonce, cipher, publicKey);
    nonce = cipher;
    encrypted = true;
}

void CertMSG::decryptNonce(CryptoPP::RSA::PrivateKey privateKey)
{
    std::string recovered;
    Encryption::decrypt(nonce, recovered, privateKey);
    nonce = recovered;
    encrypted = false;
}

AuthMSG::AuthMSG()
{

}

AuthMSG::AuthMSG(std::string data, std::string signature)
{
    this->data = data;
    this->signature = signature;
}

std::string AuthMSG::serialize(void)
{
    std::stringstream out;
    std::string str;
    
    serializeString(out, data);
    serializeString(out, signature);

    str = out.str();

    return str;
}

void AuthMSG::deserialize(std::string str)
{
    std::stringstream in;
    in.str(str);

    deserializeString(in, data);
    deserializeString(in, signature);
}