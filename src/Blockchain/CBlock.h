//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_BLOCK_INCLUDED__
#define __C_BLOCK_INCLUDED__
#include "CLog.h"
#include "CTransaction.h"
#include <string>
#include <openssl/sha.h>
#include <sys/time.h>
#include <ctime>
#include <vector>
#include <chrono>

#include "CTimeUtils.h"

namespace DeFile::Blockchain
{
    class CWallet;

    class CBlock
    {
    private:
        //Block Header - Hashed data
        uint32_t mVersion;                              // Block version
        uint64_t mBlockNum;                             // Block number
        uint8_t mHash[SHA256_DIGEST_LENGTH];            // Current hash
        uint8_t mPrevHash[SHA256_DIGEST_LENGTH];        // Prev hash 
        CBlock* mPrevBlock;                             // Pointer to the previous block, will be null 
        uint8_t mBlockOwnerHash[SHA256_DIGEST_LENGTH];  // Hash of the block owner (used for modification verification)
        uint8_t* mData;                                 // Byte data of the transactions - We can use this to maybe sneak in some messages into the block :) (Also called "Static Data")
        uint32_t mDataSize;                             // Size of the data
        uint64_t mCreatedTS;                            // Timestamp of block creation
        uint32_t mNonce;                                // Nonce of the block

        //Block transaction data - Hashed
        std::vector<std::string> mTransactions; // Vector of signed transaction hex strings

        //Stored data block - Not Hashed (Also called "Dynamic Data")
        std::vector<uint8_t> mDynamicData; //Vectors are pretty cool :)
        uint32_t mDynamicDataSize; //This limits the size of the stored data to ~4GiB and makes the chain more managable with segmentation.

        CLog mLog;
    public:
        CBlock(uint32_t version, CBlock* prevBlock, const uint8_t* hash = 0); // Constructor
        ~CBlock();                                      //
        void calculateHash(uint8_t* ret = 0);           // Calculates sha256 hash
        uint8_t* getHash();                             // Gets current hash -> mHash
        std::string getHashStr();                       // Gets the string representation of mHash
        CBlock* getPrevBlock();                         // Gets a pointer of the previous block
        void appendStaticData(uint8_t* data, uint32_t size);  // Appends data to the mData (hashed later on)
        void appendDynamicData(std::vector<uint8_t> data); // Appends the non-hashed data to the block
        bool isDifficulty(int difficulty);              // Difficulty
        void mine(int difficulty);                      // Mine the block 
        uint32_t getNonce();                            // Gets the nonce value

        uint64_t getTotalBlockSize();

        //Adds a foreign transaction to the block (needs to be pre-signed). It also assumes that it's valid - make sure to confirm somewhere else.
        //void addTransaction(std::string &signedTx, unsigned char* pubKey, CChain* chain);
        void addTransaction(std::string signedTx);

        uint32_t getVersion() { return mVersion; }
        void setVersion(uint32_t version) { mVersion = version; }
        uint64_t getBlockNum() { return mBlockNum; }
        void setBlockNum(uint64_t blockNum) { mBlockNum = blockNum; }

        bool hasHash();                                     //
        bool hasPrevHash();                                     //
        uint8_t* getPrevHash();                                 //
        std::string getPrevHashStr();                           //
        void setPrevHash(const uint8_t* prevHash);              //
        void setPrevBlock(CBlock* block);                       //

        uint64_t getCreatedTS();                                  //
        void setCreatedTS(uint64_t createdTS);                    //
        void setNonce(uint32_t nonce);                          //
        uint32_t getStaticDataSize();                                 //
        void setStaticDataSize(uint32_t size);                                 //
        uint8_t* getStaticData();                                     //
        void setAllocatedData(uint8_t* data, uint32_t sz);      //
        std::vector<std::string> getTransactions() { return mTransactions; }
        void setTransactions(std::vector<std::string> &transactions) { mTransactions = transactions; }

        uint32_t getDynamicDataSize();
        void setDynamicDataSize(uint32_t size);
        std::vector<uint8_t>* getDynamicData();

        bool isValid();
    };

}

#endif