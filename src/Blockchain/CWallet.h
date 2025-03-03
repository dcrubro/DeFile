//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_WALLET_INCLUDED__
#define __C_WALLET_INCLUDED__
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <random>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>

#include "CTransaction.h"
#include "CChain.h"
#include "CBlock.h"

namespace DeFile::Blockchain {
    class CWallet {
        private:
            unsigned char* mPubKey;
            //RSA* mPrivKey;
            unsigned char* mPrivKey;
            std::string mWalletAddress;
            int mPubKeyLen;
        public:
            CWallet(bool generateNew);
            ~CWallet();

            void generateKeypair();
            void generateKeypairFromPriv(bool save = false);
            static std::string pubKeyToWalletAddress(const unsigned char* pubKey, size_t pubKeyLen);
            static std::vector<std::string> splitTransactionData(const std::string& data);
            static uint64_t getAddressBalance(const std::string &address, CChain *chain);
            std::string signTransaction(const CTransaction* tx);
            static bool verifyTransaction(const std::string& sigHex, const unsigned char* pubKey, CChain *chain);

            bool checkWalletExistance();
            bool loadFromDisk();
            bool saveToDisk();

            unsigned char* getPubKey() const { return mPubKey; }
            unsigned char* getPrivKey() const { return mPrivKey; }
            std::string getPubKeyStr() const;
            std::string getPrivKeyStr() const;
            std::string getWalletAddress() const { return mWalletAddress; }
            int getPubKeyLen() { return mPubKeyLen; }
    };
}

#endif