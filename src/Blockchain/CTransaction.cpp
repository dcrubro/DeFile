//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CTransaction.h"

namespace DeFile::Blockchain {
    CTransaction::~CTransaction() {}

    void CTransaction::calculateHash(uint8_t* ret)
    {
        //source + destination address, transfered amount, timestamp
        uint32_t sz = sizeof(uint8_t) + (sizeof(char) * mSourceAddress.size()) + (sizeof(char) * mDestinationAddress.size()) + sizeof(uint64_t) + sizeof(uint64_t);
        mTxSize = sz;

        uint8_t* buf = new uint8_t[sz];
        uint8_t* ptr = buf;         // ptr is just a cursor

        memcpy(ptr, &mVersion, sizeof(uint8_t));
        ptr += sizeof(uint8_t);
        memcpy(ptr, mSourceAddress.c_str(), sizeof(char) * mSourceAddress.size());
        ptr += sizeof(char) * mSourceAddress.size();
        memcpy(ptr, mDestinationAddress.c_str(), sizeof(char) * mDestinationAddress.size());
        ptr += sizeof(char) * mDestinationAddress.size();
        memcpy(ptr, &mTransferedAmount, sizeof(uint64_t));
        ptr += sizeof(uint64_t);
        memcpy(ptr, &mTimestamp, sizeof(uint64_t));
        ptr += sizeof(uint64_t);

        // libssl hashing
        SHA256_CTX sha256;
        SHA256_Init(&sha256);
        SHA256_Update(&sha256, buf, sz);
        if(ret)
            SHA256_Final(ret, &sha256);
        else
            SHA256_Final(mTxHash, &sha256);

        delete[] buf;
    }


    uint8_t* CTransaction::getHash()
    {
        return mTxHash;
    }

    // hex format of hash
    std::string CTransaction::getHashStr()
    {
        char buf[SHA256_DIGEST_LENGTH * 2 + 1];
        char* ptr = buf;
        memset(buf, 0, SHA256_DIGEST_LENGTH);
        for(uint32_t n = 0; n < SHA256_DIGEST_LENGTH; n++)
        {
            sprintf(ptr, "%02x", mTxHash[n]);
            ptr += 2;
        }
        buf[SHA256_DIGEST_LENGTH * 2] = 0;
        return std::string(buf);
    }

    uint16_t CTransaction::getTxSize() {
        return mTxSize + sizeof(uint16_t) + sizeof(uint8_t);
    }

    uint16_t CTransaction::getTxSizeSerialized() {
        return this->serialize().size();
    }
}