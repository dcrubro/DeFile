//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_CRYPTOUTILS_INCLUDED__
#define __C_CRYPTOUTILS_INCLUDED__
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <string>
#include <iostream>

namespace DeFile::Blockchain::Crypto {
    class CryptoUtils {
        public:
            static RSA* loadPublicKeyFromPEM(const std::string &pubKeyPem) {
                BIO* bio = BIO_new_mem_buf(pubKeyPem.c_str(), -1);
                if (!bio) {
                    std::cerr << "Error creating BIO" << std::endl;
                    return nullptr;
                }
            
                RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
            
                if (!rsa) {
                    std::cerr << "Error loading public key from PEM: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
                }
            
                return rsa;
            }

            static RSA* loadRSAFromString(const std::string &privKeyStr) {
                BIO* bio = BIO_new_mem_buf(privKeyStr.data(), privKeyStr.size());
                if (!bio) {
                    std::runtime_error("Failed to create BIO");
                    return nullptr;
                }
            
                RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
            
                if (!rsa) {
                    std::runtime_error("Failed to read RSA private key");
                }
            
                return rsa;
            }

            static void sha256(const unsigned char* data, size_t len, unsigned char* out) {
                SHA256_CTX ctx;
                SHA256_Init(&ctx);
                SHA256_Update(&ctx, data, len);
                SHA256_Final(out, &ctx);
            }

            static std::string bytesToHex(const unsigned char* data, size_t length) {
                std::stringstream ss;
                for (size_t i = 0; i < length; ++i) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
                }
                return ss.str();
            }
        
            static std::vector<unsigned char> hexToBytes(const std::string& hex) {
                std::vector<unsigned char> bytes;
                for (size_t i = 0; i < hex.length(); i += 2) {
                    std::string byteString = hex.substr(i, 2);
                    bytes.push_back(static_cast<unsigned char>(std::stoi(byteString, nullptr, 16)));
                }
                return bytes;
            }
    };
}

#endif