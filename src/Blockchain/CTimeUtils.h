//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TIMEUTILS_INCLUDED__
#define __C_TIMEUTILS_INCLUDED__
#include <chrono>
#include <cstdint>

namespace DeFile::Blockchain {
    class CTimeUtils {
        public:
            static uint64_t getUnixTimestampNS() { //Nanosecond percision might be a bit overkill
                return std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
            }
    };
}

#endif