//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TRANSACTION_INCLUDED__
#define __C_TRANSACTION_INCLUDED__
#include <string.h>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <cstdint>
#include <time.h>

#include "CTimeUtils.h"
#include "Crypto/CCryptoUtils.h"

namespace DeFile::Blockchain {
    class CTransaction {
        private:
            uint8_t mVersion;
            std::string mSourceAddress;
            std::string mDestinationAddress;
            uint64_t mTransferedAmount;
            uint64_t mSourceNewBalance;
            uint64_t mDestinationNewBalance;
            uint64_t mTimestamp;
            uint8_t mTxHash[SHA256_DIGEST_LENGTH];
            
            uint16_t mTxSize; // Size of the transaction. This should only be accessed after hashing.
        public:
            CTransaction(uint8_t version, const std::string &srcAddr, const std::string &destAddr, uint64_t amount, uint64_t srcBal, uint64_t destBal)
             : mVersion(version), mSourceAddress(srcAddr), mDestinationAddress(destAddr), mTransferedAmount(amount), mSourceNewBalance(srcBal), mDestinationNewBalance(destBal), mTimestamp(CTimeUtils::getUnixTimestampNS()) {
                memset(mTxHash, 0, SHA256_DIGEST_LENGTH);     // mHash nulls 
            }
            ~CTransaction();

            void calculateHash(uint8_t* ret = 0);                           // Calculates sha256 hash
            std::string serialize() const {
                std::string hash = getHashStr();

                std::stringstream ss;
                ss << std::to_string(mVersion) 
                    << "," << mSourceAddress 
                    << "," << mDestinationAddress 
                    << "," << std::to_string(mTransferedAmount) 
                    << "," << std::to_string(mSourceNewBalance) 
                    << "," << std::to_string(mDestinationNewBalance) 
                    << "," << std::to_string(mTimestamp) 
                    << "," << hash;
                return ss.str();
            }

            uint8_t getVersion() { return mVersion; }
            std::string getSourceAddress() { return mSourceAddress; }
            std::string getDestinationAddress() { return mDestinationAddress; }
            uint64_t getTransferedAmount() { return mTransferedAmount; }
            time_t getTimestamp() { return mTimestamp; }
            uint8_t* getHash();                                             // Gets current hash -> mHash
            std::string getHashStr() const;                                       // Gets the string representation of mHash
            uint16_t getTxSize();                                           // Returns the size of the transaction + other data. This should be called after the hashing process.
            uint16_t getTxSizeSerialized();                                 // Returns the size of the serialized transaction + other data. This should be called after the hashing process.
        
            //Statics
            static std::string decodeTransaction(const std::string &signedTx) {
                std::vector<unsigned char> signedData = Crypto::CryptoUtils::hexToBytes(signedTx);
                return std::string(signedData.begin(), signedData.end() - 64);
            }
    };
}

#endif