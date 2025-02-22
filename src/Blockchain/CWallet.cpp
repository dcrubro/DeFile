//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CWallet.h"
#include "Crypto/CCryptoUtils.h"

namespace DeFile::Blockchain {
    CWallet::CWallet(bool generateNew, int bits) : mPrivKey(nullptr), mPubKey(nullptr), mPubKeyLen(0), mBits(bits) {
        std::cout << "CWallet Constructor: Initializing..." << std::endl;

        if (generateNew) {
            generateKeypair(bits);
        } else {
            std::cout << "CWallet: Checking wallet existence..." << std::endl;
            if (checkWalletExistance()) {
                if (!this->loadFromDisk()) {
                    throw std::runtime_error("Failed to load wallet from disk.");
                }
            } else {
                throw std::runtime_error("Wallet does not exist. Initialize with `true`.");
            }
        }

        std::cout << "CWallet Constructor: Initialization complete." << std::endl;
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

        // Ensure mPubKey is initially null
        if (mPubKey) {
            OPENSSL_free(mPubKey);
            mPubKey = nullptr;
        }

        // Get the public key from the private key
        unsigned char* tempPubKey = nullptr;
        mPubKeyLen = i2d_RSA_PUBKEY(mPrivKey, &tempPubKey);
        if (mPubKeyLen <= 0) {
            std::cerr << "Error extracting public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            RSA_free(mPrivKey);
            BN_free(bn);
            return;
        }

        // Allocate memory and copy the key
        mPubKey = new unsigned char[mPubKeyLen];
        memcpy(mPubKey, tempPubKey, mPubKeyLen);
        OPENSSL_free(tempPubKey);

        // Hash the public key using SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(mPubKey, mPubKeyLen, hash);

        // Convert hash to hex string and generate the wallet address
        mWalletAddress = "df1a" + bytesToHex(hash, SHA256_DIGEST_LENGTH).substr(0, 50);

        // Clean up the big number used for RSA generation
        BN_free(bn);

        std::cout << "CWallet: Keypair generated successfully." << std::endl;

        saveToDisk();
    }

    void CWallet::mGenerateKeypairFromPriv() {
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        // Generate RSA private key
        mPrivKey = RSA_new();
        BIGNUM* bn = BN_new();
        BN_set_word(bn, RSA_F4);  // public exponent (65537)

        if (RSA_generate_key_ex(mPrivKey, mBits, bn, nullptr) != 1) {
            std::cerr << "Error generating RSA key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            RSA_free(mPrivKey);
            BN_free(bn);
            return;
        }

        // Extract public key from private key
        unsigned char* tempPubKey = nullptr;
        mPubKeyLen = i2d_RSA_PUBKEY(mPrivKey, &tempPubKey);
        if (mPubKeyLen <= 0) {
            std::cerr << "Error getting public key: " << ERR_error_string(ERR_get_error(), nullptr) << std::endl;
            RSA_free(mPrivKey);
            BN_free(bn);
            return;
        }

        // Allocate memory for mPubKey and copy contents
        mPubKey = new unsigned char[mPubKeyLen];
        memcpy(mPubKey, tempPubKey, mPubKeyLen);
        OPENSSL_free(tempPubKey); // Free the buffer allocated by OpenSSL

        // Hash the public key using SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(mPubKey, mPubKeyLen, hash);

        // Convert hash to hex string and generate the wallet address
        mWalletAddress = "df1a" + bytesToHex(hash, SHA256_DIGEST_LENGTH).substr(0, 50);

        // Clean up
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

        RSA* rsaPubKey = Crypto::CryptoUtils::loadPublicKeyFromPEM(pubKeyPEM);
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

    bool CWallet::checkWalletExistance() {
        std::string walletFn("data/wallet");
        std::cout << "Made it to checking.";
        //Some stupid code to check existance (basically it will return NULL if it doesn't exist).
        FILE* file = fopen(walletFn.c_str(), "rb");
        bool r = file != NULL;
        fclose(file);
        return r;
    }

    bool CWallet::loadFromDisk() {
        std::string walletFn("data/wallet");
        FILE* file = fopen(walletFn.c_str(), "rb");
        if (!file) {
            return false;
        }

        size_t r = fread(&mBits, sizeof(uint16_t), 1, file);
        if (r != 1) {
            fclose(file);
            throw std::runtime_error("Failed to read bit size from wallet file.");
        }

        uint32_t len = 0;
        r = fread(&len, sizeof(uint32_t), 1, file);
        if (r != 1) {
            fclose(file);
            throw std::runtime_error("Failed to read key length from wallet file.");
        }

        char* privKeyBuffer = new char[len + 1];  // Allocate buffer
        r = fread(privKeyBuffer, sizeof(char), len, file);
        fclose(file);

        if (r != len) {
            delete[] privKeyBuffer;
            throw std::runtime_error("Failed to read private key from wallet file.");
        }

        privKeyBuffer[len] = '\0'; // Ensure null termination
        std::cout << sizeof(privKeyBuffer) << "\n";

        mPrivKey = Crypto::CryptoUtils::loadRSAFromString(std::string(privKeyBuffer));
        delete[] privKeyBuffer;  // Free buffer

        std::cout << mPrivKey;

        if (!mPrivKey) {
            //TODO: Fix this
            throw std::runtime_error("Failed to reconstruct RSA key from disk.");
        }

        return true;
    }

    bool CWallet::saveToDisk() {
        std::string walletFn("data/wallet");
        FILE* file = fopen(walletFn.c_str(), "wb");
        if (file) {
            std::string priv = this->getPrivKey();
            //std::cout << priv << "\n";
            uint32_t len = priv.size();
            std::cout << len;
            fwrite(&mBits, sizeof(uint16_t), 1, file);
            fwrite(&len, sizeof(uint32_t), 1, file);
            fwrite(&priv, sizeof(char), len, file);
            fclose(file);

            return true;
        }

        return false;
    }
}