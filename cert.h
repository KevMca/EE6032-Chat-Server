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

        /* Functions */

        // Saves a private RSA key to a byte file
        // Inputs -> key: either a public key or private key object
        //           fileName: the file location to save the key to
        // Returns -> 0 if no errors
        template< typename T>
        static int saveKey(T key, const char *fileName);

        // Reads a private RSA key from a byte file
        // Inputs -> fileName: the file location to save the key to
        // Outputs -> key: either a public key or private key object
        template< typename T>
        static T readKey(const char *fileName);

        // Prints a private key in hex format
        // Inputs -> privateKey: complimentary private RSA key
        // Returns -> 0 if no errors
        static int printPrivateKey(CryptoPP::RSA::PrivateKey privateKey);

        // Prints a public key in hex format
        // Inputs -> publicKey: complimentary public RSA key
        // Returns -> 0 if no errors
        static int printPublicKey(CryptoPP::RSA::PublicKey publicKey);

        // Saves the certificate to a byte file
        // Inputs -> fileName: the file location to save the key to
        // Returns -> 0 if no errors
        int save(const char *fileName);

        // Creates a private and public key pair given `keySize`
        // Inputs -> keySize: size (in bits) of the RSA key
        // Outputs -> privateKey: complimentary private RSA key (must be deleted externally)
        //            this->publicKey: complimentary public RSA key
        // Returns -> 0 if no errors
        CryptoPP::RSA::PrivateKey createKeys(unsigned int keySize);

        // Signs the certificate using a 
        // Inputs -> privateCAKey: the private key of the certificate authority that is signing the cert
        // Returns -> 0 if no errors
        int sign(CryptoPP::RSA::PrivateKey privateCAKey);

        // Signs the certificate and compares against the included certificate signature.
        // Inputs -> publicCAKey: the public key of the certificate authority that signed the cert
        // Returns -> "true" if the signatures match, "false" if signatures do not match
        bool verify(CryptoPP::RSA::PublicKey publicCAKey);

        // Converts a public or private key to a string
        // Inputs -> key: either a public key or private key object
        // Returns -> A string representing a public or private key
        template< typename T>
        static std::string keyToString(T key);

    private:
        // Writes a string to a file
        // Inputs -> out: output filestream to write to
        //           data: the string data to write to the file
        static void writeString(std::ostream &out, const std::string &data);

        // Reads a string from a file
        // Inputs -> in: input filestream to read from
        // Outputs -> data: the string data that was read
        static void readString(std::istream &in, std::string &data);

        // Converts a string to a public key
        // Inputs -> publicKeyString: the string that contains a public key
        // Returns -> A string representing a public key
        CryptoPP::RSA::PublicKey stringToPublicKey(std::string publicKeyString);

        // Converts the subject name and public key to a string
        // Returns -> The combination of the subject name and public key
        std::string contentsToString(void);
};
