//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __I_NET_INCLUDED__
#define __I_NET_INCLUDED__
#include "CPacket.h"

namespace DeFile::Blockchain
{
    namespace Net
    {
        class INet
        {
        public:
            int mSocket;    // socket handle
            CPacket recvPacket();   // receive packet of data
            void sendPacket(CPacket* packet);   // send packet of data
        protected:
            INet();
        private:
            const uint32_t mChunkSize = 2048;   // chunk data size

            uint16_t recvUInt16();
            void sendUInt16(uint16_t num);
            uint32_t recvUInt();
            void sendUInt(uint32_t num);
            int32_t recvInt();
            void sendInt(int32_t num);
            uint64_t recvUInt64();
            void sendUInt64(uint64_t num);
            uint8_t* recvDataAlloc(uint64_t size);
            void sendData(uint8_t* data, uint64_t size);
        };
    }
}

#endif