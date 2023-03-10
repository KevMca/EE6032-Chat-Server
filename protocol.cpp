
#include "protocol.h"


/* SockMSG */


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

int SockMSG::readMSG(SOCKET socket)
{
    char buffer[DEFAULT_BUFLEN] = { 0 };
    int nBytes = recv(socket, buffer, DEFAULT_BUFLEN, 0);
    
    if (nBytes > 0) {
        deserialize(buffer);
    }

    return nBytes;
}

int SockMSG::sendMSG(SOCKET socket)
{
    std::string serial = serialize();
    const char *msg = serial.c_str();
    int nBytes = send(socket, msg, (int)strlen(msg), 0);

    return nBytes;
}


/* CertMSG */


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


/* ChallengeMSG */


ChallengeMSG::ChallengeMSG()
{

}

ChallengeMSG::ChallengeMSG(std::string response)
{
    this->response = response;
}

std::string ChallengeMSG::serialize(void)
{
    std::stringstream out;
    std::string str, challengeString, responseString;

    CryptoPP::StringSource ss1(challenge, true, 
        new CryptoPP::HexEncoder( new CryptoPP::StringSink(challengeString) )
    );
    CryptoPP::StringSource ss2(response, true, 
        new CryptoPP::HexEncoder( new CryptoPP::StringSink(responseString) )
    );
    
    serializeString(out, challengeString);
    serializeString(out, responseString);

    str = out.str();

    return str;
}

void ChallengeMSG::deserialize(std::string str)
{
    std::stringstream in;
    std::string challengeHex, responseHex;
    in.str(str);

    deserializeString(in, challengeHex);
    deserializeString(in, responseHex);

    CryptoPP::StringSource ss1(challengeHex, true, 
        new CryptoPP::HexDecoder( new CryptoPP::StringSink(this->challenge) )
    );
    CryptoPP::StringSource ss2(responseHex, true, 
        new CryptoPP::HexDecoder( new CryptoPP::StringSink(this->response) )
    );
}

void ChallengeMSG::generateChallenge(void)
{
    this->challenge = Encryption::generateNonce();
}

void ChallengeMSG::encryptNonces(CryptoPP::RSA::PublicKey publicKey)
{
    std::string challengeCipher, responseCipher;
    Encryption::encrypt(challenge, challengeCipher, publicKey);
    Encryption::encrypt(response, responseCipher, publicKey);
    
    challenge = challengeCipher;
    response = responseCipher;
    encrypted = true;
}

void ChallengeMSG::decryptNonces(CryptoPP::RSA::PrivateKey privateKey)
{
    std::string challengeRecovered, responseRecovered;
    Encryption::decrypt(challenge, challengeRecovered, privateKey);
    Encryption::decrypt(response, responseRecovered, privateKey);
    
    challenge = challengeRecovered;
    response  = responseRecovered;
    encrypted = false;
}

/* AgreementMSG */


AgreementMSG::AgreementMSG()
{

}

std::string AgreementMSG::serialize(void)
{
    std::stringstream out;
    std::string str, nonceString;

    CryptoPP::StringSource ss1(nonce, true, 
        new CryptoPP::HexEncoder( new CryptoPP::StringSink(nonceString) )
    );
    
    serializeString(out, nonceString);

    str = out.str();

    return str;
}

void AgreementMSG::deserialize(std::string str)
{
    std::stringstream in;
    std::string nonceHex;
    in.str(str);

    deserializeString(in, nonceHex);

    CryptoPP::StringSource ss1(nonceHex, true, 
        new CryptoPP::HexDecoder( new CryptoPP::StringSink(this->nonce) )
    );
}

void AgreementMSG::generateNonce(void)
{
    this->nonce = Encryption::generateNonce();
}

void AgreementMSG::encryptNonce(CryptoPP::RSA::PublicKey publicKey)
{
    std::string nonceCipher;
    Encryption::encrypt(nonce, nonceCipher, publicKey);
    
    nonce = nonceCipher;
    encrypted = true;
}

void AgreementMSG::decryptNonce(CryptoPP::RSA::PrivateKey privateKey)
{
    std::string nonceRecovered;
    Encryption::decrypt(nonce, nonceRecovered, privateKey);
    
    nonce = nonceRecovered;
    encrypted = false;
}


/* AuthMSG */


AuthMSG::AuthMSG()
{

}

AuthMSG::AuthMSG(SockMSG *msg, std::string source, std::string destination, CryptoPP::RSA::PrivateKey privateKey)
{
    this->type = typeid(*msg).name() + 6;
    this->source = source;
    this->destination = destination;
    this->msg = msg->serialize();
    this->signature = createSignature(privateKey);
}

AuthMSG::AuthMSG(std::string msg, std::string source, std::string destination, CryptoPP::RSA::PrivateKey privateKey)
{
    this->type = "undefined";
    this->source = source;
    this->destination = destination;
    this->msg = msg;
    this->signature = createSignature(privateKey);
}

std::string AuthMSG::serialize(void)
{
    std::stringstream out;
    std::string str;
    
    serializeString(out, type);
    serializeString(out, source);
    serializeString(out, destination);
    serializeString(out, msg);
    serializeString(out, signature);

    str = out.str();

    return str;
}

void AuthMSG::deserialize(std::string str)
{
    std::stringstream in;
    in.str(str);

    deserializeString(in, type);
    deserializeString(in, source);
    deserializeString(in, destination);
    deserializeString(in, msg);
    deserializeString(in, signature);
}

bool AuthMSG::verify(CryptoPP::RSA::PublicKey publicKey)
{
    using namespace CryptoPP;

    // Convert from hex
    std::string signatureHex;
    StringSource ss(signature, true,
        new HexDecoder( new StringSink(signatureHex) )
    );

    // Append signature to contents
    std::string signedMsg = msg;
    signedMsg.insert( signedMsg.end(), signatureHex.begin(), signatureHex.end() );

    // Verify the signature and contents
    std::string recovered;
    bool result = Encryption::verify(signedMsg, recovered, publicKey);
    
    return result;
}

std::string AuthMSG::createSignature(CryptoPP::RSA::PrivateKey privateKey)
{
    using namespace CryptoPP;

    // Sign the contents
    std::string signature, signatureHex;
    Encryption::sign(msg, signature, privateKey);

    // Remove msg from the signature
    signature.erase(0, msg.length());

    // Convert to hex
    StringSource ss(signature, true,
        new HexEncoder( new StringSink(signatureHex) )
    );
    
    return signatureHex;
}
