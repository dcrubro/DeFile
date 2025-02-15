//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "Storage.h"
#include "CStorageNone.h"
#include "CStorageLocal.h"

namespace DeFile::Blockchain
{
    namespace Storage
    {
        IStorage* createStorage(E_STORAGE_TYPE type)
        {
            if(type == EST_LOCAL)
                return new CStorageLocal();
            else if(type == EST_NONE)
                return new CStorageNone();
            return 0;
        }
    }
}
