//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CBlock.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "CWallet.h"

namespace DeFile::Blockchain
{

    CBlock::CBlock(uint32_t version, CBlock* prevBlock, const uint8_t* hash) : mLog("Block") {
        mPrevBlock = prevBlock;
        if(hash)
            memcpy(mHash, hash, SHA256_DIGEST_LENGTH);
        else
            memset(mHash, 0, SHA256_DIGEST_LENGTH);     // mHash nulls 
        if(mPrevBlock)
            memcpy(mPrevHash, mPrevBlock->getHash(), SHA256_DIGEST_LENGTH);   // Copy previous block hash to current objects previous block hash
        else
            memset(mPrevHash, 0, SHA256_DIGEST_LENGTH); // mPrevHash to nulls
        mVersion = version;
        mBlockNum = 0;
        mCreatedTS = CTimeUtils::getUnixTimestampNS(); // Set creation timestamp
        mNonce = 0;
        mDataSize = 0;
        mData = 0;

        mDynamicData = {};
        mDynamicDataSize = 0;
        if(!hash)
            calculateHash();
    }

    CBlock::~CBlock() {
        if (mData)
            delete[] mData;
        
        mTransactions.clear();
        mTransactions.shrink_to_fit();
        
        mDynamicData.clear();
        mDynamicData.shrink_to_fit();
    }

    void CBlock::calculateHash(uint8_t* ret) {
        uint32_t szTxs = 0;
        uint32_t sz = sizeof(uint32_t) + sizeof(uint64_t) + (SHA256_DIGEST_LENGTH * sizeof(uint8_t)) + sizeof(uint64_t) + sizeof(uint32_t) + mDataSize;

        //Add the size of the transactions to actually allocate the correct size.
        for (int i = 0; i < mTransactions.size(); i++) {
            uint32_t szTx = mTransactions[i].size();
            sz += szTx;
        }

        uint8_t* buf = new uint8_t[sz];
        uint8_t* ptr = buf;         // ptr is just a cursor

        memcpy(ptr, &mVersion, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &mBlockNum, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        memcpy(ptr, mPrevHash, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
        ptr += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
        memcpy(ptr, &mCreatedTS, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        if(mDataSize != 0)
        {
            memcpy(ptr, mData, mDataSize);
            ptr += mDataSize;
        }
        memcpy(ptr, &mNonce, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        for (int i = 0; i < mTransactions.size(); i++) {
            uint32_t szTx = mTransactions[i].size();

            memcpy(ptr, mTransactions[i].c_str(), szTx);
            ptr += szTx;
        }

        // libssl hashing
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buf, sz);
        if(ret)
            SHA256_Final(ret, &sha256);
        else
            SHA256_Final(mHash, &sha256);

        delete[] buf;
    }


    uint8_t* CBlock::getHash()
    {
        return mHash;
    }

    // hex format of hash
    std::string CBlock::getHashStr()
    {
        char buf[SHA256_DIGEST_LENGTH * 2 + 1];
        char* ptr = buf;
        memset(buf, 0, SHA256_DIGEST_LENGTH);
        for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
        {
            sprintf(ptr, "%02x", mHash[n]);
            ptr += 2;
        }
        buf[SHA256_DIGEST_LENGTH * 2] = 0;
        return std::string(buf);
    }

    // pointer to the previous block
    CBlock* CBlock::getPrevBlock()
    {
        return mPrevBlock;
    }

    void CBlock::appendStaticData(uint8_t* data, uint32_t size) {
        uint8_t* newData = new uint8_t[mDataSize + size];
        uint8_t* ptr = newData;
        if (mDataSize != 0) {
            memcpy(ptr, mData, mDataSize);
            ptr += mDataSize;
            delete[] mData;
        }
        memcpy(ptr, data, size);
        mData = newData;
        mDataSize += size;
    }

    void CBlock::appendDynamicData(std::vector<uint8_t> data) {
        mDynamicDataSize += data.size();
        mDynamicData.insert(mDynamicData.end(), data.begin(), data.end());
    }

    bool CBlock::isDifficulty(int difficulty)
    {
        for(uint32_t n = 0; n < difficulty; n++)
        {
            if(mHash[n] != 0)
                return false;   
        }
        return true;
    }

    void CBlock::mine(int difficulty)
    {
        while(!isDifficulty(difficulty))
        {
            mNonce++;
            calculateHash();
            usleep(10);
        }        
    }

    uint32_t CBlock::getNonce() {
        return mNonce;
    }

    uint64_t CBlock::getTotalBlockSize() {
        //Header size (mostly static)
        uint64_t sz = sizeof(SHA256_DIGEST_LENGTH) * 3 + mDataSize + sizeof(uint64_t) + sizeof(uint32_t);
        
        for (std::string &tx : mTransactions) {
            sz += tx.size();
        }

        sz += mDynamicDataSize;

        return sz;
    }
    
    /*void CBlock::addTransaction(std::string &signedTx, unsigned char* pubKey, CChain* chain) {
        //std::cout << signedTx << "\n";
        if (CWallet::verifyTransaction(signedTx, pubKey, chain)) {
            mTransactions.push_back(signedTx);
            mLog.writeLine("Added foreign transaction to current block.");
            return;
        }
        mLog.writeLine("Could not verify transaction. Did not add.");
    }*/

    void CBlock::addTransaction(std::string signedTx) {
        mTransactions.push_back(signedTx);
        mLog.writeLine("Added foreign transaction to current block.");
    }

    bool CBlock::hasHash()
    {
        for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
        {
            if(mHash[n] != 0)
                return true;
        }
        return false;
    }

    bool CBlock::hasPrevHash()
    {
        for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
        {
            if(mPrevHash[n] != 0)
                return true;
        }
        return false;
    }

    uint8_t* CBlock::getPrevHash()
    {
        return mPrevHash;
    }

    std::string CBlock::getPrevHashStr()
    {
        char buf[SHA256_DIGEST_LENGTH * 2 + 1];
        char* ptr = buf;
        memset(buf, 0, SHA256_DIGEST_LENGTH);
        for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
        {
            sprintf(ptr, "%02x", mPrevHash[n]);
            ptr += 2;
        }
        buf[SHA256_DIGEST_LENGTH * 2] = 0;
        return std::string(buf);
    }

    void CBlock::setPrevHash(const uint8_t* prevHash)
    {
        memcpy(mPrevHash, prevHash, SHA256_DIGEST_LENGTH);
    }

    void CBlock::setPrevBlock(CBlock* block)
    {
        mPrevBlock = block;
        setPrevHash(mPrevBlock->getHash());
    }

    uint64_t CBlock::getCreatedTS()
    {
        return mCreatedTS;
    }

    void CBlock::setCreatedTS(uint64_t createdTS)
    {
        mCreatedTS = createdTS;
    }

    void CBlock::setNonce(uint32_t nonce)
    {
        mNonce = nonce;
    }

    uint32_t CBlock::getStaticDataSize() {
        return mDataSize;
    }

    void CBlock::setStaticDataSize(uint32_t size) {
        mDataSize = size;
    }

    uint8_t* CBlock::getStaticData() {
        return mData;
    }

    void CBlock::setAllocatedData(uint8_t* data, uint32_t sz) {
        if(mData)
            delete[] mData;
        mData = data;
        mDataSize = sz;
    }

    uint32_t CBlock::getDynamicDataSize() {
        return mDynamicDataSize;
    }

    void CBlock::setDynamicDataSize(uint32_t size) {
        mDynamicDataSize = size;
    }

    std::vector<uint8_t>* CBlock::getDynamicData() {
        return &mDynamicData;
    }

    bool CBlock::isValid() {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        memset(hash, 0, SHA256_DIGEST_LENGTH);
        calculateHash(hash);

        /*char buf[SHA256_DIGEST_LENGTH * 2 + 1];
        char* ptr = buf;
        memset(buf, 0, SHA256_DIGEST_LENGTH);
        for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
        {
            sprintf(ptr, "%02x", mPrevHash[n]);
            ptr += 2;
        }
        buf[SHA256_DIGEST_LENGTH * 2] = 0;
        std::cout << std::string(buf) << "\n";*/

        /*for (int i = 0; i < mTransactions.size(); i++) {
            std::cout << mTransactions[i] << "\n";
        }*/

        return memcmp(mHash, hash, SHA256_DIGEST_LENGTH) == 0;
    }
}