//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __E_MESSAGE_TYPE_INCLUDED__
#define __E_MESSAGE_TYPE_INCLUDED__

namespace DeFile::Blockchain
{
    namespace Net
    {
        enum EMessageType
        {
            EMT_NULL,
            EMT_PING,
            EMT_ACK,
            EMT_ERR,
            EMT_NODE_REGISTER,
            EMT_NODE_REGISTER_PORT,
            EMT_INIT_CHAIN,
            EMT_WRITE_BLOCK,
            EMT_CHAIN_NEW,
            EMT_CHAIN_INFO,
            EMT_COUNT
        };
    }
}

#endif