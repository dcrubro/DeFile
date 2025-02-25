//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "INet.h"
#include <stdexcept>
#include <netinet/in.h>
#include <string.h>

namespace DeFile::Blockchain
{
    namespace Net
    {
        INet::INet()
        {
            mSocket = 0;
        }

        CPacket INet::recvPacket()
        {
            if(mSocket == 0)
                throw std::runtime_error("INet: Socket is null.");
            CPacket packet;
            packet.mVersion = recvUInt();
            packet.mMessageType = (EMessageType)recvUInt();
            packet.mNonce = recvUInt();
            packet.mCreatedTS = (uint64_t)recvUInt64();
            // Hash
            uint8_t* hashData = recvDataAlloc(SHA256_DIGEST_LENGTH);
            memcpy(packet.mHash, hashData, SHA256_DIGEST_LENGTH);
            delete[] hashData;
            // Prev hash
            hashData = recvDataAlloc(SHA256_DIGEST_LENGTH);
            memcpy(packet.mPrevHash, hashData, SHA256_DIGEST_LENGTH);
            delete[] hashData;
            packet.mDataSize = recvUInt();
            if (packet.mDataSize != 0) {
                packet.mData = recvDataAlloc(packet.mDataSize);
                packet.mTrackDataAlloc = true;
            }

            //Recieve the count of transactions
            uint32_t txAmount = recvUInt();
            for (int i = 0; i < txAmount; i++) {
                uint16_t txSize = recvUInt16(); //Recover the tx size

                //Start reading the bytes and construct them into an std::string and push them back to the mTransactions vector
                uint8_t *buf = new uint8_t[txSize];
                memcpy(buf, recvDataAlloc(txSize), txSize);

                std::string tx(reinterpret_cast<const char*>(buf), txSize);
                delete[] buf; //Safely free buffer

                packet.mTransactions.push_back(tx);
            }

            return packet;
        }

        void INet::sendPacket(CPacket* packet)
        {
            if(mSocket == 0)
                throw std::runtime_error("INet: Socket is null.");
            sendUInt(packet->mVersion);
            sendUInt(packet->mMessageType);
            sendUInt(packet->mNonce);
            sendUInt64(packet->mCreatedTS);
            sendData(packet->mHash, SHA256_DIGEST_LENGTH);
            sendData(packet->mPrevHash, SHA256_DIGEST_LENGTH);
            sendUInt(packet->mDataSize);
            if(packet->mDataSize != 0 && packet->mData)
                sendData(packet->mData, packet->mDataSize);
            
            //First tell the receiver how many transactions exist in the packet, so they can target the right amount of data
            uint32_t txAmount = packet->mTransactions.size();
            sendUInt(txAmount);

            //Send the transactions
            for (int i = 0; i < txAmount; i++) {
                std::string tx = packet->mTransactions[i];

                //Send the tx size since the reciever won't know it
                uint16_t txSize = tx.size();
                sendUInt16(txSize);

                //Construct the raw byte array to send
                uint8_t *buf = new uint8_t[txSize];
                memcpy(buf, tx.data(), txSize);

                sendData(buf, txSize); //Send

                delete[] buf; //Free the memory
            }
        }

        uint16_t INet::recvUInt16() {
            uint16_t netNum = 0;
            if(recv(mSocket, (void*)&netNum, sizeof(uint16_t), 0) < 0)
                throw std::runtime_error("Failed to receive UINT16.");
            return ntohl(netNum);
        }

        void INet::sendUInt16(uint16_t num) {
            uint16_t netNum = htonl(num);
            if(send(mSocket, (void*)&netNum, sizeof(uint16_t), 0) < 0)
                throw std::runtime_error("Failed to send UINT16.");
        }

        uint32_t INet::recvUInt()
        {
            uint32_t netNum = 0;
            if(recv(mSocket, (void*)&netNum, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to receive UINT32.");
            return ntohl(netNum);
        }

        void INet::sendUInt(uint32_t num)
        {
            uint32_t netNum = htonl(num);
            if(send(mSocket, (void*)&netNum, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to send UINT32.");
        }

        int32_t INet::recvInt()
        {
            uint32_t netNum = 0;
            if(recv(mSocket, (void*)&netNum, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to receive INT32.");
            return ntohl(netNum);
        }

        void INet::sendInt(int32_t num)
        {
            uint32_t netNum = htonl((uint32_t)num);
            if(send(mSocket, (void*)&netNum, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to send INT32.");
        }

        uint64_t INet::recvUInt64()
        {
            uint32_t netHigh = 0;
            uint32_t netLow = 0;
            if(recv(mSocket, (void*)&netHigh, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to receive UINT64 (H).");
            if(recv(mSocket, (void*)&netLow, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to receive UINT64 (L).");

            return (((uint64_t)ntohl(netHigh) & 0xFFFFFFFFLL) << 32) | ((uint64_t)ntohl(netLow) >> 32);
        }

        void INet::sendUInt64(uint64_t num)
        {
            uint32_t netHigh = htonl((uint32_t)(num >> 32));
            uint32_t netLow = htonl((uint32_t)(num & 0xFFFFFFFFLL));
            if(send(mSocket, (void*)&netHigh, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to send UINT64 (H).");
            if(send(mSocket, (void*)&netLow, sizeof(uint32_t), 0) < 0)
                throw std::runtime_error("Failed to send UINT64 (L).");
        }

        uint8_t* INet::recvDataAlloc(uint64_t size)
        {
            uint32_t chunkSize = mChunkSize;
            uint8_t* data = new uint8_t[size];
            uint8_t* ptr = data;
            while(ptr < (data + size))
            {
                if((ptr + chunkSize) > (data + size))
                    chunkSize = (data + size - ptr);
                ssize_t r = recv(mSocket, (void*)ptr, sizeof(uint8_t) * chunkSize, 0);
                if(r < 0)
                    throw std::runtime_error("Failed to receive data chunk.");                
                ptr += r;
            }
            return data;
        }

        void INet::sendData(uint8_t* data, uint64_t size)
        {
            uint32_t chunkSize = mChunkSize;
            uint8_t* ptr = data;
            while(ptr < (data+size))
            {
                if((ptr + chunkSize) > (data + size))
                    chunkSize = (data + size - ptr);
                ssize_t r = send(mSocket, (void*)ptr, sizeof(uint8_t) * chunkSize, 0);
                if(r < 0)
                    throw std::runtime_error("Failed to send data chunk.");
                ptr += r;
            }
        }
    }
}
