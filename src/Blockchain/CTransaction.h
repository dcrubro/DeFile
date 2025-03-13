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
    //By the version 1 transaction definition, a raw, non-signed, non-serialized transaction is 173 bytes long.
    //The final size of a fully signed, serialized and stringified transaction is 552 bytes, and it's stored in the final block.
    class CTransaction {
        private:
            uint8_t mVersion;
            std::string mSourceAddress;
            std::string mDestinationAddress;
            uint64_t mTransferredAmount;
            uint64_t mSourceNewBalance;
            uint64_t mDestinationNewBalance;
            uint64_t mTimestamp; //Note: This timestamp indicates when the transaction was defined, not when it was signed or when it was validated in a block.
                                 //The real timestamp of when the network will indicate the transaction took place will still be the corresponding block's timestamp.
            uint8_t mTxHash[SHA256_DIGEST_LENGTH];
            
            uint16_t mTxSize; // Size of the transaction. This should only be accessed after hashing.
        public:
            CTransaction(uint8_t version, const std::string &srcAddr, const std::string &destAddr, uint64_t amount, uint64_t srcBal, uint64_t destBal)
             : mVersion(version), mSourceAddress(srcAddr), mDestinationAddress(destAddr), mTransferredAmount(amount), mSourceNewBalance(srcBal), mDestinationNewBalance(destBal), mTimestamp(CTimeUtils::getUnixTimestampNS()) {
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
                    << "," << std::to_string(mTransferredAmount) 
                    << "," << std::to_string(mSourceNewBalance) 
                    << "," << std::to_string(mDestinationNewBalance) 
                    << "," << std::to_string(mTimestamp) 
                    << "," << hash;
                return ss.str();
            }

            uint8_t getVersion() { return mVersion; }
            std::string getSourceAddress() { return mSourceAddress; }
            std::string getDestinationAddress() { return mDestinationAddress; }
            uint64_t getTransferedAmount() { return mTransferredAmount; }
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