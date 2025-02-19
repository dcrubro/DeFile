//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_WALLET_INCLUDED__
#define __C_WALLET_INCLUDED__
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <iostream>
#include <iomanip>
#include <string>

#include "CTransaction.h"

namespace DeFile::Blockchain {
    class CWallet {
        private:
            unsigned char* mPubKey;
            RSA* mPrivKey;
            std::string mWalletAddress;
            int mPubKeyLen;
        public:
            CWallet(int bits);
            ~CWallet();

            void generateKeypair(int bits = 2048);
            std::string bytesToHex(const unsigned char* data, size_t length) const;
            std::string signTransaction(const CTransaction* tx);
            bool verifyTransaction(const CTransaction* tx, const std::string& sig, const std::string& pubKeyPEM);

            std::string getPubKey() const;
            std::string getPrivKey() const;
            std::string getWalletAddress() const { return mWalletAddress; }
            int getPubKeyLen() { return mPubKeyLen; }
    };
}

#endif