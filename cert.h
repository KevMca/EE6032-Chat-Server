// Header file for creating certificates and manipulating their keys
//
// Sources:
// 

// Cryptography includes
#include <cryptopp/cryptlib.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

// Represents a public key certificate and includes functions for saving, loading and verifying
// Notation: subjectName, publicKey, {H(subjectName, publicKey)}kcert^-1
// Example:
//      Certificate cert(subjectName);
//      CryptoPP::RSA::PrivateKey privateKey = cert.createKeys(2048);
//      cert.sign(CAKey);
class Certificate {
    public:
        std::string subjectName;
        CryptoPP::RSA::PublicKey publicKey;
        std::string signature;

        /* Constructors */

        // Construct certificate with subject name only, usually new keys are generated using the
        // createKeys() function and then signed with the sign() function
        // Inputs -> subjectName: the name of the subject of the certificate
        explicit Certificate(std::string subjectName);

        // Construct certificate from a byte file
        // Inputs -> fileName: the location where the certificate is stored
        explicit Certificate(const char *fileName);

        /* Instance functions */

        // Saves the certificate to a byte file
        // Inputs -> fileName: the file location to save the key
        void save(const char *fileName);

        // Creates a private and public key pair with a key size given in bits
        // Inputs -> keySize: size (in bits) of the RSA key
        // Outputs -> this->publicKey: public RSA key object
        // Returns -> private RSA key object
        CryptoPP::RSA::PrivateKey createKeys(unsigned int keySize);

        // Signs the certificate using a private key
        // Inputs -> CAKey: the private key of the certificate authority that is signing the cert
        void sign(CryptoPP::RSA::PrivateKey privateCAKey);

        // Signs the certificate and compares against the included certificate signature.
        // Inputs -> publicCAKey: the public key of the certificate authority that signed the cert
        // Returns -> "true" if the signatures match, "false" if signatures do not match
        bool verify(CryptoPP::RSA::PublicKey publicCAKey);

        /* Static key functions */

        // Saves a public or private key to a byte file
        // Inputs -> key: either a public key or private key object
        //           fileName: the file location to save the key to
        // Returns -> 0 if no errors
        template< typename T>
        static void saveKey(T key, const char *fileName);

        // Reads a public or private key from a byte file
        // Inputs -> fileName: the file location to save the key to
        // Outputs -> key: either a public key or private key object
        template< typename T>
        static T readKey(const char *fileName);

        // Converts a public or private key to a string
        // Inputs -> key: either a public key or private key object
        // Returns -> A string representing a public or private key
        template< typename T>
        static std::string keyToString(T key);

        // Converts a hex encoded string to a public or private key
        // Inputs -> keyString: the string that contains a hex encoded public or private key
        // Returns -> A public or private key object
        template< typename T>
        T stringToKey(std::string keyString);

        // Prints a public or private key in hex format
        // Inputs -> key: either a public key or private key object
        template< typename T>
        static void printKey(T key);

    private:
        // Writes a string to a file
        // Inputs -> out: output filestream to write to
        //           data: the string data to write to the file
        static void writeString(std::ostream &out, const std::string &data);

        // Reads a string from a file
        // Inputs -> in: input filestream to read from
        // Outputs -> data: the string data that was read
        static void readString(std::istream &in, std::string &data);

        // Converts the subject name and public key to a string
        // Returns -> The combination of the subject name and public key
        std::string contentsToString(void);
};
