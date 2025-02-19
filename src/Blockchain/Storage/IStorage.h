//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __I_STORAGE_INCLUDED__
#define __I_STORAGE_INCLUDED__
#include "../CBlock.h"
#include <vector>

namespace DeFile::Blockchain
{
    namespace Storage
    {
        class IStorage
        {
        public:
            virtual void loadChain(std::vector<CBlock*>* chain) = 0;    // Load chain into memory
            virtual void saveChain(std::vector<CBlock*>* chain) = 0;    // Save chain to disk

            virtual void load(CBlock* block) = 0;                       // Load block
            virtual void save(CBlock* block, uint64_t blockCount, bool checkExistance) = 0;  // Save block

            virtual void dispose() = 0;                                 // dispose 
        };
    }
}

#endif