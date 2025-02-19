//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CTransaction.h"

namespace DeFile::Blockchain {
    CTransaction::~CTransaction() {}

    void CTransaction::calculateHash(uint8_t* ret)
    {
        //source + destination address, transfered amount, timestamp
        uint32_t sz = (sizeof(char) * mSourceAddress.size()) * 2 + sizeof(uint64_t) + sizeof(time_t);
        mTxSize = sz;

        uint16_t* buf = new uint16_t[sz];
        uint16_t* ptr = buf;         // ptr is just a cursor

        memcpy(ptr, &mSourceAddress, sizeof(std::string) * mSourceAddress.size());
        ptr += sizeof(std::string) * mSourceAddress.size();
        memcpy(ptr, &mDestinationAddress, sizeof(std::string) * mDestinationAddress.size());
        ptr += sizeof(std::string) * mDestinationAddress.size();
        memcpy(ptr, &mTransferedAmount, sizeof(uint32_t));
        ptr += sizeof(uint32_t);
        memcpy(ptr, &mTimestamp, sizeof(time_t));
        ptr += sizeof(time_t);

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
}