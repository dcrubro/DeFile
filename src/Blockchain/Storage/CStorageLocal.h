//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_STORAGE_LOCAL_INCLUDED__
#define __C_STORAGE_LOCAL_INCLUDED__
#include "IStorage.h"
#include "../CBlock.h"
#include "../CChain.h"
#include "../CLog.h"
#include <string>
#include <vector>
#include <map>

namespace DeFile::Blockchain
{
    namespace Storage
    {
        class CStorageLocal : public IStorage
        {
        private:
            static std::string mDefaultBasePath;
            const uint32_t Version = 1;
            const std::string mBasePath = std::string("data/");
            const uint32_t mChunkSize = 2048;
            std::map<std::string, std::basic_string<uint8_t>> mMetaData;

            CLog mLog;
        public:
            static void setDefaultBasePath(const std::string& path);

            CStorageLocal();
            ~CStorageLocal();

            virtual void loadChain(std::vector<CBlock*>* chain);

            virtual void load(CBlock* block);
            virtual void save(CBlock* block, uint64_t blockCount);

            void loadMetaData();
            void saveMetaData();

            virtual void dispose();
        };
    }
}

#endif