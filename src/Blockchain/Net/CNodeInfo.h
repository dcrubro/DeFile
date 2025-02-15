//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_NODE_INFO_INCLUDED__
#define __C_NODE_INFO_INCLUDED__
#include <time.h>
#include <string>

namespace DeFile::Blockchain
{
    namespace Net
    {
        class CNodeInfo
        {
        public:
            std::string mHostName;
            uint32_t mPort;
            time_t mLastSeen;

            CNodeInfo(const std::string& hostname, uint32_t port)
            {
                mHostName = hostname;
                mPort = port;
                mLastSeen = time(0);
            }

            void seen()
            {
                mLastSeen = time(0);
            }
        };
    }
}
#endif