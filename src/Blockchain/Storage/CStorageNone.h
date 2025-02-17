//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_STORAGE_NONE_INCLUDED__
#define __C_STORAGE_NONE_INCLUDED__
#include "IStorage.h"
#include "../CBlock.h"

namespace DeFile::Blockchain
{
    namespace Storage
    {
        class CStorageNone : public IStorage
        {
        public:
            virtual void loadChain(std::vector<CBlock*>* chain) {};
            virtual void saveChain(std::vector<CBlock*>* chain) {};

            virtual void load(CBlock* block) {}
            virtual void save(CBlock* block, uint64_t blockCount) {}

            virtual void dispose() { delete this; }
        };
    }
}

#endif