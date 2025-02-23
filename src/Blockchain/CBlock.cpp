//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CBlock.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

namespace DeFile::Blockchain
{

    CBlock::CBlock(CBlock* prevBlock, const uint8_t* hash) : mLog("Block") {
        mPrevBlock = prevBlock;
        if(hash)
            memcpy(mHash, hash, SHA256_DIGEST_LENGTH);
        else
            memset(mHash, 0, SHA256_DIGEST_LENGTH);     // mHash nulls 
        if(mPrevBlock)
            memcpy(mPrevHash, mPrevBlock->getHash(), SHA256_DIGEST_LENGTH);   // Copy previous block hash to current objects previous block hash
        else
            memset(mPrevHash, 0, SHA256_DIGEST_LENGTH); // mPrevHash to nulls
        mCreatedTS = CTimeUtils::getUnixTimestampNS(); // Set creation timestamp
        mNonce = 0;
        mDataSize = 0;
        mData = 0;
        if(!hash)
            calculateHash();
    }

    CBlock::~CBlock() {
        if(mData)
            delete[] mData;
    }

    void CBlock::calculateHash(uint8_t* ret) {
        uint32_t szTxs = 0;
        uint32_t sz = (SHA256_DIGEST_LENGTH * sizeof(uint8_t)) + sizeof(uint64_t) + sizeof(uint32_t);

        uint8_t* buf = new uint8_t[sz];
        uint8_t* ptr = buf;         // ptr is just a cursor

        memcpy(ptr, mPrevHash, SHA256_DIGEST_LENGTH * sizeof(uint8_t));
        ptr += SHA256_DIGEST_LENGTH * sizeof(uint8_t);
        memcpy(ptr, &mCreatedTS, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        /*if(mDataSize != 0)
        {
            memcpy(ptr, mData, mDataSize);
            ptr += mDataSize;
        }*/
        memcpy(ptr, &mNonce, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        for (int i = 0; i < mTransactions.size(); i++) {
            uint32_t szTx = mTransactions[i].size();
            sz += szTx;

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

    void CBlock::appendData(uint8_t* data, uint32_t size)
    {
        uint8_t* newData = new uint8_t[mDataSize + size];
        uint8_t* ptr = newData;
        if(mDataSize != 0)
        {
            memcpy(ptr, mData, mDataSize);
            ptr += mDataSize;
            delete[] mData;
        }
        memcpy(ptr, data, size);
        mData = newData;
        mDataSize += size;
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

    uint32_t CBlock::getNonce()
    {
        return mNonce;
    }

    void CBlock::addTransactionWithSign(CTransaction* tx, CWallet* srcWallet) {
        tx->calculateHash();
        this->mTransactions.push_back(srcWallet->signTransaction(tx));
        mLog.writeLine("Added transaction " + tx->getHashStr() + " to current block.");
    }
    
    void CBlock::addTransaction(std::string &signedTx) {
        //std::cout << signedTx << "\n";
        this->mTransactions.push_back(signedTx);
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

    uint32_t CBlock::getDataSize()
    {
        return mDataSize;
    }

    uint8_t* CBlock::getData()
    {
        return mData;
    }

    void CBlock::setAllocatedData(uint8_t* data, uint32_t sz)
    {
        if(mData)
            delete[] mData;
        mData = data;
        mDataSize = sz;
    }

    bool CBlock::isValid()
    {
        uint8_t hash[SHA256_DIGEST_LENGTH];
        memset(hash, 0, SHA256_DIGEST_LENGTH);
        calculateHash(hash);
        return memcmp(mHash, hash, SHA256_DIGEST_LENGTH) == 0;
    }
}