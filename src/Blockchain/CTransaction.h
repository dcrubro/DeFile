//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TRANSACTION_INCLUDED__
#define __C_TRANSACTION_INCLUDED__
#include <string.h>
#include <string>
#include <sstream>
#include <openssl/sha.h>
#include <cstdint>
#include <time.h>

namespace DeFile::Blockchain {
    class CTransaction {
        private:
            uint8_t mVersion;
            std::string mSourceAddress;
            std::string mDestinationAddress;
            uint64_t mTransferedAmount;
            time_t mTimestamp;
            uint8_t mTxHash[SHA256_DIGEST_LENGTH];
            
            uint16_t mTxSize; // Size of the transaction. This should only be accessed after hashing.

            uint8_t mDecimals = 12; //Currency decimal count. Effective transfer is mTransferedAmount / decimals.
        public:
            CTransaction(uint8_t version, const std::string &srcAddr, const std::string &destAddr, uint64_t amount)
             : mVersion(version), mSourceAddress(srcAddr), mDestinationAddress(destAddr), mTransferedAmount(amount), mTimestamp(time(0)) {
                memset(mTxHash, 0, SHA256_DIGEST_LENGTH);     // mHash nulls 
            }
            ~CTransaction();

            void calculateHash(uint8_t* ret = 0);                           // Calculates sha256 hash
            std::string serialize() const {
                //Convert the hash to a string
                char buf[SHA256_DIGEST_LENGTH * 2 + 1];
                char* ptr = buf;
                memset(buf, 0, SHA256_DIGEST_LENGTH);
                for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
                {
                    sprintf(ptr, "%02x", mTxHash[n]);
                    ptr += 2;
                }
                buf[SHA256_DIGEST_LENGTH * 2] = 0;

                std::stringstream ss;
                ss << std::to_string(mVersion) << "," << mSourceAddress << "," << mDestinationAddress << "," << std::to_string(mTransferedAmount) << "," << std::to_string(mTimestamp) << "," << std::string(buf);
                return ss.str();
            }

            uint8_t getVersion() { return mVersion; }
            std::string getSourceAddress() { return mSourceAddress; }
            std::string getDestinationAddress() { return mDestinationAddress; }
            uint64_t getTransferedAmount() { return mTransferedAmount; }
            time_t getTimestamp() { return mTimestamp; }
            uint8_t getDecimals() { return mDecimals; }
            uint8_t* getHash();                                             // Gets current hash -> mHash
            std::string getHashStr();                                       // Gets the string representation of mHash
            uint16_t getTxSize();                                           // Returns the size of the transaction + other data. This should be called after the hashing process.
    };
}

#endif