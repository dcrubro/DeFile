//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_CONSTANTS_INCLUDED__
#define __C_CONSTANTS_INCLUDED__

#include <string>
#include <cstdint>

namespace DeFile::Blockchain::Constants {
    class CConstants {
        public:
            const std::string SYSTEM_WALLET = "dfsysfffffffffffffffffffffff00000000000000000000000000"; //System wallet which distributes fee rewards
            const std::string MINT_WALLET = "dfmintffffffffffffffffffffff00000000000000000000000000"; //System wallet which mints new tokens. This is the only wallet on the network which can send infinite tokens.
            const uint64_t CYCLE_TIME_NANOS = 604800000000000;
            const uint8_t DECIMALS = 12; //Currency decimal count. Effective transfer is mTransferedAmount / decimals.
    };
}

#endif