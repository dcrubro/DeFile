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
        TXTMSG = 4,
        DISCONNECT = 255
    };
}

#endif