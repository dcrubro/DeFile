//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CWallet.h"
#include "Crypto/CCryptoUtils.h"

namespace DeFile::Blockchain {
    CWallet::CWallet(bool generateNew) : mPrivKey(nullptr), mPubKey(nullptr), mPubKeyLen(0) {
        std::cout << "CWallet Constructor: Initializing..." << std::endl;

        if (generateNew) {
            generateKeypair();
        } else {
            std::cout << "CWallet: Checking wallet existence..." << std::endl;
            if (checkWalletExistance()) {
                if (!this->loadFromDisk()) {
                    throw std::runtime_error("Failed to load wallet from disk.");
                }
            } else {
                throw std::runtime_error("Wallet does not exist. Initialize with true.");
            }
        }

        std::cout << "CWallet Constructor: Initialization complete." << std::endl;
    }

    CWallet::~CWallet() {
        if (mPrivKey) {
            delete[] mPrivKey;
        }

        if (mPubKey) {
            delete[] mPubKey;
        }
    }

    void CWallet::generateKeypair() {
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        //Generate a random 32-byte (256-bit) private key
        unsigned char privateKey[32];
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<unsigned char> dist(0, 255);

        do {
            for (int i = 0; i < 32; ++i) {
                privateKey[i] = dist(gen);
            }
        } while (!secp256k1_ec_seckey_verify(ctx, privateKey));

        //Store the key
        mPrivKey = new unsigned char[32];
        memcpy(mPrivKey, privateKey, 32);

        //Generate the public key
        secp256k1_pubkey publicKey;
        if (!secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey)) {
            std::cerr << "CWallet: Error generating secp256k1 public key\n";
            secp256k1_context_destroy(ctx);
            return;
        }

        //Serialize (compress) the public key
        unsigned char serializedPublicKey[33];
        size_t publicKeyLen = sizeof(serializedPublicKey);
        secp256k1_ec_pubkey_serialize(ctx, serializedPublicKey, &publicKeyLen, &publicKey, SECP256K1_EC_COMPRESSED);

        //Store the public key
        mPubKeyLen = publicKeyLen;
        mPubKey = new unsigned char[mPubKeyLen];
        memcpy(mPubKey, serializedPublicKey, mPubKeyLen);

        //Hash the public key with SHA256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(mPubKey, mPubKeyLen, hash);

        //Convert to address
        mWalletAddress = "df1a" + Crypto::CryptoUtils::bytesToHex(hash, SHA256_DIGEST_LENGTH).substr(0, 50);

        std::cout << "CWallet: Keypair generated successfully." << std::endl;

        //Clean up
        secp256k1_context_destroy(ctx);

        this->saveToDisk();
    }

    void CWallet::generateKeypairFromPriv(bool save) {
        if (!mPrivKey) {
            std::cerr << "CWallet: Private key is not set\n";
            return;
        }

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        //Validate the private key
        if (!secp256k1_ec_seckey_verify(ctx, mPrivKey)) {
            std::cerr << "CWallet: Invalid private key\n";
            secp256k1_context_destroy(ctx);
            return;
        }

        //Generate the public key
        secp256k1_pubkey publicKey;
        if (!secp256k1_ec_pubkey_create(ctx, &publicKey, mPrivKey)) {
            std::cerr << "CWallet: Error generating secp256k1 public key\n";
            secp256k1_context_destroy(ctx);
            return;
        }

        //Serialize (compress) the public key
        unsigned char serializedPublicKey[33];
        size_t publicKeyLen = sizeof(serializedPublicKey);
        secp256k1_ec_pubkey_serialize(ctx, serializedPublicKey, &publicKeyLen, &publicKey, SECP256K1_EC_COMPRESSED);

        //Store the public key
        mPubKeyLen = publicKeyLen;
        mPubKey = new unsigned char[mPubKeyLen];
        memcpy(mPubKey, serializedPublicKey, mPubKeyLen);

        //Hash the public key with SHA256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(mPubKey, mPubKeyLen, hash);

        //Convert to address
        mWalletAddress = "df1a" + Crypto::CryptoUtils::bytesToHex(hash, SHA256_DIGEST_LENGTH).substr(0, 50);

        std::cout << "CWallet: Keypair generated successfully." << std::endl;

        //Clean up
        secp256k1_context_destroy(ctx);

        if (save)
            this->saveToDisk();
    }

    std::string CWallet::getPubKeyStr() const {
        return std::string(reinterpret_cast<char const*>(mPubKey));
    }

    std::string CWallet::getPrivKeyStr() const {
        //std::cout << std::string(reinterpret_cast<char const*>(mPrivKey)) << "\n";
        return std::string(reinterpret_cast<char const*>(mPrivKey));
    }

    std::string pubKeyToWalletAddress(const unsigned char* pubKey, size_t pubKeyLen) {
        if (pubKeyLen != 33 && pubKeyLen != 65) {
            throw std::invalid_argument("Invalid public key length! Expected 33 (compressed) or 65 (uncompressed) bytes.");
        }

        // Hash the public key using SHA-256
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(pubKey, pubKeyLen, hash);

        // Convert the hash to hex and create the wallet address
        std::string walletAddress = "df1a" + Crypto::CryptoUtils::bytesToHex(hash, SHA256_DIGEST_LENGTH).substr(0, 50);

        return walletAddress;
    }

    std::vector<std::string> splitTransactionData(const std::string& data) {
        std::vector<std::string> components;
        std::stringstream ss(data);
        std::string item;

        while (std::getline(ss, item, ',')) {
            components.push_back(item);
        }

        return components;
    }

    uint64_t getAddressBalance(const std::string &address, CChain *chain) {
        if (!address.c_str()) {
            std::cerr << "CWallet: Address is null\n";
            return 0;
        }
        
        if (!chain) {
            std::cerr << "CWallet: Chain reference pointer not provided\n";
            return 0;
        }

        //Find the latest block with a reference to the address (reference to the tx timestamp)
        CBlock *cur = chain->getCurrentBlock();
        while (cur) {
            //Get the transaction list
            std::vector<std::string> txs = cur->getTransactions();
            
            for (const std::string &tx : txs) {
                std::string data = CTransaction::decodeTransaction(tx);
                //Read the src and dest address and look for a match
                std::vector<std::string> components = splitTransactionData(data);
                if (components[0] == "1") { //Handle TX Version 1
                    //NOTE: If a wallet sends to itself, then the srcNewBalance will equal the destNewBalance. This means that it doesn't really matter which
                    //one we check in that edge case.

                    if (components[1] == address) { //Handle being sender
                        return std::stoull(components[4]); //Arg 4 is srcNewBalance
                    }

                    if (components[2] == address) { //Handle being receiver
                        return std::stoull(components[5]); //Arg 4 is destNewBalance
                    }
                }
            }


            cur = cur->getPrevBlock();
        }

        return 0; //No data found, set balance to 0.
    }

    std::string CWallet::signTransaction(const CTransaction* tx) {
        if (!tx) {
            std::cerr << "CWallet: Transaction is null\n";
            return "";
        }

        if (!mPrivKey) {
            std::cerr << "CWallet: Private key is not set\n";
            return "";
        }

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

        //Serialize the transaction data
        std::string transactionData = tx->serialize();

        unsigned char hash[32];
        Crypto::CryptoUtils::sha256(reinterpret_cast<const unsigned char*>(transactionData.c_str()), transactionData.size(), hash);

        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_sign(ctx, &sig, hash, mPrivKey, nullptr, nullptr)) {
            throw std::runtime_error("CWallet: Failed to sign transaction");
        }

        //Serialize the signature
        unsigned char serializedSig[64]; //64-byte compact sig
        secp256k1_ecdsa_signature_serialize_compact(ctx, serializedSig, &sig);

        //Concatenate message + sig;
        std::vector<unsigned char> signedData(transactionData.begin(), transactionData.end());
        signedData.insert(signedData.end(), serializedSig, serializedSig + 64);

        return Crypto::CryptoUtils::bytesToHex(signedData.data(), signedData.size());
    }

    bool verifyTransaction(const std::string& sigHex, const unsigned char* pubKey, CChain *chain) {
        if (sigHex.empty()) {
            std::cerr << "CWallet: Signature Hex is null\n";
            return false;
        }

        if (!pubKey) {
            std::cerr << "CWallet: Public key is not set\n";
            return false;
        }

        if (!chain) {
            std::cerr << "CWallet: Chain reference not provided\n";
            return false;
        }

        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);

        std::vector<unsigned char> signedData = Crypto::CryptoUtils::hexToBytes(sigHex);

        if (signedData.size() < 64) return false; // Signature size check

        //Extract the original message
        std::string extractedMessage = std::string(signedData.begin(), signedData.end() - 64);

        //Hash the extracted message
        unsigned char hash[32];
        Crypto::CryptoUtils::sha256(reinterpret_cast<const unsigned char*>(extractedMessage.c_str()), extractedMessage.size(), hash);

        //Extract the signature
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signedData.data() + signedData.size() - 64)) {
            return false;
        }

        //Load the public key
        secp256k1_pubkey pubKeyStruct;
        if (!secp256k1_ec_pubkey_parse(ctx, &pubKeyStruct, pubKey, sizeof(pubKey))) {
            return false;
        }

        //Verify the signature
        bool sigMatches = secp256k1_ecdsa_verify(ctx, &sig, hash, &pubKeyStruct) == 1;

        //Split the data and generate the wallet address from the public key to verify source wallet
        std::vector<std::string> components = splitTransactionData(extractedMessage);
        std::string sourceWalletAddress = pubKeyToWalletAddress(pubKey, 33);
        bool walletMatches = (components[0] == "1" && components[1] == sourceWalletAddress); //First arg is always TX version, for version 1 transactions, second arg is source address, assume 33 for pubKey size (TODO fix later)

        //Ensure that the sender actually has enough balance to send the transaction. We can do this by finding the last block with the mentioned address, 
        //and reading its balance.
        uint64_t senderBalance = getAddressBalance(sourceWalletAddress, chain);
        uint64_t sendAmount = std::stoull(components[4]);
        uint64_t newBalCalc = senderBalance - sendAmount;

        return sigMatches && walletMatches && (newBalCalc >= 0);
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
        //TODO: Encrypt the private key before saving it - this is a security issue right now.

        std::string walletFn("data/wallet");
        FILE* file = fopen(walletFn.c_str(), "rb");
        if (!file) {
            return false; // No wallet file found
        }

        uint32_t len = 0;
        size_t r = fread(&len, sizeof(uint32_t), 1, file);
        if (r != 1 || len != 32) {  // Ensure length is correct
            fclose(file);
            throw std::runtime_error("Failed to read valid key length from wallet file.");
        }

        unsigned char privKeyBuffer[32];  // Fixed-size array (avoids heap allocation)
        r = fread(privKeyBuffer, sizeof(char), len, file);
        fclose(file);

        if (r != len) {
            throw std::runtime_error("Failed to read private key from wallet file.");
        }

        // Allocate and store private key
        if (mPrivKey) {
            delete[] mPrivKey;
        }
        mPrivKey = new unsigned char[32];
        memcpy(mPrivKey, privKeyBuffer, 32);

        std::cout << "Loaded Private Key: " << Crypto::CryptoUtils::bytesToHex(mPrivKey, 32) << "\n";

        generateKeypairFromPriv(false); // Regenerate public key from loaded private key

        return true;
    }

    bool CWallet::saveToDisk() {
        std::string walletFn("data/wallet");
        FILE* file = fopen(walletFn.c_str(), "wb");
        if (!file) {
            return false;
        }

        uint32_t len = 32;  // Private key is always 32 bytes
        fwrite(&len, sizeof(uint32_t), 1, file);
        fwrite(mPrivKey, sizeof(char), len, file);
        fclose(file);

        std::cout << "Saved Private Key: " << Crypto::CryptoUtils::bytesToHex(mPrivKey, 32) << "\n";

        return true;
    }

}