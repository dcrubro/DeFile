//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __E_MESSAGETYPE_INCLUDED__
#define __E_MESSAGETYPE_INCLUDED__

#include <cstdint>

namespace DeFile::Blockchain::ANet {
    enum class EMessageType : uint8_t {
        UNKNOWN = 0,
        HELLO = 1,
        PING = 2,
        PONG = 3,
        TXTMSG = 4, //Text Message
        REQSYN = 5, //Request Sync
        SYNBLK = 6, //Sync Block (Block data)
        BRODTX = 7, //Broadcast Transaction
        GETBLK = 8, //Get Block (by hash)
        GETBLKID = 9, //Get Block (by id)
        DISCONNECT = 255
    };
}

#endif