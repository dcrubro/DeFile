//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_CONSTANTS_INCLUDED__
#define __C_CONSTANTS_INCLUDED__

#include "../../MUtil.h"
#include <string>
#include <cstdint>

namespace DeFile::Blockchain::Constants {
    class CConstants {
        public:
            //Prevent initialization
            CConstants() = delete;
            DISABLE_COPY_AND_MOVE(CConstants);

            static constexpr const char* SYSTEM_WALLET = "dfsysfffffffffffffffffffffff00000000000000000000000000"; //System wallet which distributes fee rewards
            static constexpr const char* MINT_WALLET = "dfmintffffffffffffffffffffff00000000000000000000000000"; //System wallet which mints new tokens. This is the only wallet on the network which can send infinite tokens.
            static constexpr uint64_t CYCLE_TIME_NANOS = 604800000000000; //Global cycle length - 7 days
            static constexpr uint8_t DECIMALS = 9; //Currency decimal count. Effective transfer is mTransferedAmount / 10^decimals.
    };
}

#endif