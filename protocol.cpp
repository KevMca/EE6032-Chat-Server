
#include "protocol.h"


/* BaseMSG */

int BaseMSG::readMSG(SOCKET socket)
{
    char buffer[DEFAULT_BUFLEN] = { 0 };
    int nBytes = recv(socket, buffer, DEFAULT_BUFLEN, 0);
    
    if (nBytes > 0) {
        deserialize(buffer);
    }

    return nBytes;
}

int BaseMSG::sendMSG(SOCKET socket)
{
    std::string serial = serialize();
    const char *msg = serial.c_str();
    int nBytes = send(socket, msg, (int)strlen(msg), 0);

    return nBytes;
}

void BaseMSG::serializeString(std::ostream &out, std::string data)
{
    out << data.size();
    out << ',';
    out << data;
    out << ',';
}

void BaseMSG::deserializeString(std::istream &in, std::string &data)
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
    Encryption::asymEncrypt(nonce, cipher, publicKey);
    nonce = cipher;
    encrypted = true;
}

void CertMSG::decryptNonce(CryptoPP::RSA::PrivateKey privateKey)
{
    std::string recovered;
    Encryption::asymDecrypt(nonce, recovered, privateKey);
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

std::string ChallengeMSG::generateChallenge(void)
{
    this->challenge = Encryption::generateNonce();
    return this->challenge;
}

void ChallengeMSG::encryptNonces(CryptoPP::RSA::PublicKey publicKey)
{
    std::string challengeCipher, responseCipher;
    Encryption::asymEncrypt(challenge, challengeCipher, publicKey);
    Encryption::asymEncrypt(response, responseCipher, publicKey);
    
    challenge = challengeCipher;
    response = responseCipher;
    encrypted = true;
}

void ChallengeMSG::decryptNonces(CryptoPP::RSA::PrivateKey privateKey)
{
    std::string challengeRecovered, responseRecovered;
    Encryption::asymDecrypt(challenge, challengeRecovered, privateKey);
    Encryption::asymDecrypt(response, responseRecovered, privateKey);
    
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
    Encryption::asymEncrypt(nonce, nonceCipher, publicKey);
    
    nonce = nonceCipher;
    encrypted = true;
}

void AgreementMSG::decryptNonce(CryptoPP::RSA::PrivateKey privateKey)
{
    std::string nonceRecovered;
    Encryption::asymDecrypt(nonce, nonceRecovered, privateKey);
    
    nonce = nonceRecovered;
    encrypted = false;
}


/* AgreementMSG */


ChatMSG::ChatMSG() : iv(CryptoPP::AES::BLOCKSIZE)
{

}

std::string ChatMSG::serialize(void)
{
    using namespace CryptoPP;

    std::stringstream out;
    std::string str, messageHex, ivHex, ivString;

    StringSource ss1(this->message, true, 
        new HexEncoder( new StringSink(messageHex) )
    );

    ivString = std::string((const char*)this->iv.data(), this->iv.size());
    StringSource ss2(ivString, true, 
        new HexEncoder( new StringSink(ivHex) )
    );
    
    serializeString(out, messageHex);
    serializeString(out, ivHex);

    str = out.str();

    return str;
}

void ChatMSG::deserialize(std::string str)
{
    using namespace CryptoPP;

    std::stringstream in;
    std::string messageHex, ivHex, ivString;
    in.str(str);

    deserializeString(in, messageHex);
    deserializeString(in, ivHex);

    StringSource ss1(messageHex, true, 
        new HexDecoder( new StringSink(this->message) )
    );

    StringSource ss2(ivHex, true, 
        new HexDecoder( new StringSink(ivString) )
    );
    this->iv = SecByteBlock((const byte*)ivString.data(), ivString.size());
}

void ChatMSG::encryptMessage(std::string sharedKey)
{
    using namespace CryptoPP;

    // Generate random Initial Variation (IV)
    AutoSeededRandomPool prng;
    prng.GenerateBlock(this->iv, this->iv.size());
    
    std::string cipher;
    Encryption::symEncrypt(message, cipher, sharedKey, this->iv);
    
    message = cipher;
    encrypted = true;
}

void ChatMSG::decryptMessage(std::string sharedKey)
{
    std::string recovered;
    Encryption::symDecrypt(message, recovered, sharedKey, iv);
    
    message = recovered;
    encrypted = false;
}


/* AppMSG */


AppMSG::AppMSG()
{

}



AppMSG::AppMSG(BaseMSG *msg, std::string source, std::string destination, CryptoPP::RSA::PrivateKey privateKey)
{
    this->type = typeid(*msg).name() + 6;
    this->source = source;
    this->destination = destination;
    this->msg = msg->serialize();
    this->signature = createSignature(privateKey);
}

AppMSG::AppMSG(std::string msg, std::string source, std::string destination, CryptoPP::RSA::PrivateKey privateKey)
{
    this->type = "undefined";
    this->source = source;
    this->destination = destination;
    this->msg = msg;
    this->signature = createSignature(privateKey);
}

AppMSG::AppMSG(BaseMSG *msg, std::string source, std::string destination)
{
    this->type = typeid(*msg).name() + 6;
    this->source = source;
    this->destination = destination;
    this->msg = msg->serialize();
}

AppMSG::AppMSG(std::string msg, std::string source, std::string destination)
{
    this->type = "undefined";
    this->source = source;
    this->destination = destination;
    this->msg = msg;
}

std::string AppMSG::serialize(void)
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

void AppMSG::deserialize(std::string str)
{
    std::stringstream in;
    in.str(str);

    deserializeString(in, type);
    deserializeString(in, source);
    deserializeString(in, destination);
    deserializeString(in, msg);
    deserializeString(in, signature);
}

bool AppMSG::verify(CryptoPP::RSA::PublicKey publicKey)
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

std::string AppMSG::createSignature(CryptoPP::RSA::PrivateKey privateKey)
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
