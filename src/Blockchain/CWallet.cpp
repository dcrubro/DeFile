//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CWallet.h"

namespace DeFile::Blockchain {
    RSA* loadPublicKeyFromPEM(const std::string& pubkey_pem) {
        BIO* bio = BIO_new_mem_buf(pubkey_pem.c_str(), -1);
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

    CWallet::CWallet(int bits) : mPrivKey(nullptr), mPubKey(nullptr), mPubKeyLen(0), mBits(bits) {
        generateKeypair(bits);
    }

    CWallet::~CWallet() {
        if (mPrivKey) {
            RSA_free(mPrivKey);
        }
        if (mPubKey) {
            OPENSSL_free(mPubKey);
        }
    }

    void CWallet::generateKeypair(int bits) {
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        // Generate RSA private key
        mPrivKey = RSA_new();
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);  // public exponent (65537)

        if (RSA_generate_key_ex(mPrivKey, bits, bn, nullptr) != 1) {
            std::cerr << "Error generating RSA key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            RSA_free(mPrivKey);
            BN_free(bn);
            return;
        }

        // Get the public key from the private key
        mPubKeyLen = i2d_RSA_PUBKEY(mPrivKey, &mPubKey);
        if (mPubKeyLen == -1) {
            std::cerr << "Error getting public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            RSA_free(mPrivKey);
            BN_free(bn);
            return;
        }

        // Hash the public key using SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(mPubKey, mPubKeyLen, hash);

        // Convert hash to a string and generate the wallet address
        std::string hash_str = bytesToHex(hash, SHA256_DIGEST_LENGTH);
        mWalletAddress = "df1a" + hash_str.substr(0, 50); // Prefix with "df1a"

        // Clean up the big number used for RSA generation
        BN_free(bn);
    }

    std::string CWallet::bytesToHex(const unsigned char* data, size_t length) const {
        std::stringstream ss;
        for (size_t i = 0; i < length; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        }
        return ss.str();
    }

    std::string CWallet::getPubKey() const {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSA_PUBKEY(bio, mPrivKey);

        char* pubKeyData = nullptr;
        long pubKeyLen = BIO_get_mem_data(bio, &pubKeyData);
        
        std::string pubKey(pubKeyData, pubKeyLen);
        
        BIO_free(bio);
        
        return pubKey;
    }

    std::string CWallet::getPrivKey() const {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_RSAPrivateKey(bio, mPrivKey, nullptr, nullptr, 0, nullptr, nullptr);
        
        char* privKeyData = nullptr;
        long privKeyLen = BIO_get_mem_data(bio, &privKeyData);
        
        std::string privKey(privKeyData, privKeyLen);
        
        BIO_free(bio);
        
        return privKey;
    }

    std::string CWallet::signTransaction(const CTransaction* tx) {
        if (!tx) {
            std::cerr << "Transaction is null!" << std::endl;
            return "";
        }
    
        // Serialize the transaction data
        std::string transactionData = tx->serialize();

        // Sign the hashed transaction data
        unsigned char signature[RSA_size(mPrivKey)];
        unsigned int signatureLen;
    
        if (RSA_sign(NID_sha256, (unsigned char*)transactionData.c_str(), transactionData.size(), signature, &signatureLen, mPrivKey) != 1) {
            std::cerr << "Error signing transaction: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            return "";
        }
    
        // Convert the signature to hex format
        return bytesToHex(signature, signatureLen);
    }

    bool CWallet::verifyTransaction(const CTransaction* tx, const std::string& sig, const std::string& pubKeyPEM) {
        if (!tx) {
            std::cerr << "Transaction is null!" << std::endl;
            return false;
        }
    
        // Serialize the transaction data
        std::string transactionData = tx->serialize();
    
        // Convert the hex signature back to bytes
        size_t sigLen = sig.size() / 2;
        unsigned char* sigBytes = new unsigned char[sigLen];
        for (size_t i = 0; i < sigLen; ++i) {
            sscanf(sig.c_str() + 2 * i, "%02x", &sigBytes[i]);
        }

        RSA* rsaPubKey = loadPublicKeyFromPEM(pubKeyPEM);
        if (!rsaPubKey) {
            delete[] sigBytes;
            return false;
        } 
    
        // Verify the signature with the public key
        int result = RSA_verify(NID_sha256, (unsigned char*)transactionData.c_str(), transactionData.size(), sigBytes, sigLen, rsaPubKey);
    
        delete[] sigBytes;
        RSA_free(rsaPubKey);
    
        return result == 1;
    }

    bool CWallet::loadFromDisk() {
        std::string metaDataFn("data/wallet");
        FILE* file = fopen(metaDataFn.c_str(), "rb");
        if (file) {
            size_t r = 0;

            uint16_t bits = 0;
            r = fread(&bits, sizeof(uint16_t), 1, file);
            if (r != 1)
                throw std::runtime_error("Could not read bit size.");
            //TODO: Continue here

            fclose(file);
        }
    }

    bool CWallet::saveToDisk() {
        std::string metaDataFn("data/wallet");
        FILE* file = fopen(metaDataFn.c_str(), "wb");
        if (file) {
            fwrite(&mBits, sizeof(uint16_t), 1, file);
            fwrite(&getPrivKey(), sizeof(char) * getPrivKey().size(), 1, file);
            fwrite(&getPubKey(), sizeof(char) * getPubKey().size(), 1, file);
            fwrite(&getWalletAddress(), sizeof(char) * getWalletAddress().size(), 1, file);
            fclose(file);
        }
    }
}