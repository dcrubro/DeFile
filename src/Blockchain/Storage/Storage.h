//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __STORAGE_INCLUDED__
#define __STORAGE_INCLUDED__
#include "IStorage.h"
#include "EStorageType.h"

namespace DeFile::Blockchain
{
    namespace Storage
    {
        IStorage* createStorage(E_STORAGE_TYPE type);
    }
}

#endif