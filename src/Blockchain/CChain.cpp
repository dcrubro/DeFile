//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CChain.h"
#include "Net/CPacket.h"
#include "Storage/Storage.h"
#include <stdexcept>
#include <unistd.h>

namespace DeFile::Blockchain
{
    CChain::CChain(const std::string& hostname, uint32_t hostPort, int difficulty, Storage::E_STORAGE_TYPE storageType) : mLog("Chain")
    {
        CLog::open(false);
        mRunning = true;
        mStopped = false;
        mHostName = hostname;
        mDifficulty = difficulty;
        mNetPort = hostPort;
        mStorage = Storage::createStorage(storageType);  // initialize storage
        mServer = new Net::CServer(this, mNetPort);
        CBlock* block = new CBlock(0);
        mChain.push_back(block);  // First block (genesis)
        block->mine(mDifficulty);
        mCurrentBlock = block;
        load();
        mServer->start();
        mReady = true;
    }

    CChain::CChain(const std::string& hostname, uint32_t hostPort, bool newChain, const std::string& connectToNode, int difficulty, Storage::E_STORAGE_TYPE storageType, uint32_t connectPort) : CChain(hostname, hostPort, difficulty, storageType)
    {
        if(!newChain)
        {
            if(connectToNode.empty())
                throw std::runtime_error("When not creating a new chain, you must specify 'connectToNode'.");
            Net::CClient* client = connectNewClient(connectToNode, connectPort);
            while(!client->isReady())
                usleep(1);
            mReady = true;
            mLog.writeLine("Chain ready!");
        }
    }

    CChain::~CChain()
    {
        if(mClients.size() != 0)
        {
            for(std::vector<Net::CClient*>::iterator it = mClients.begin(); it != mClients.end(); ++it)
            {
                delete (*it);
            }
            mClients.clear();
        }
        delete mServer;
        mStorage->dispose();
        for(std::vector<CBlock*>::iterator it = mChain.begin(); it != mChain.end(); ++it)
        {
            delete (*it);
        }
        mChain.clear();
        CLog::close();
        mRunning = false;
        mLog.writeLine("Cleanup completed.");
    }

    void CChain::appendToCurrentBlock(uint8_t* data, uint32_t size)
    {
        mCurrentBlock->appendData(data, size);
    }

    void CChain::nextBlock(bool save, bool distribute)
    {
        mCurrentBlock->calculateHash();
        if(save)
            mStorage->save(mCurrentBlock, mChain.size());
        CBlock* block = new CBlock(mCurrentBlock);
        mChain.push_back(block);
        block->mine(mDifficulty);
        
        if(distribute)
            distributeBlock(mCurrentBlock);
        mCurrentBlock = block;

        if(!isValid())
            throw new std::runtime_error("Chain has been broken!");
    }

    void CChain::distributeBlock(CBlock* block)
    {
        for(std::vector<Net::CClient*>::iterator it = mClients.begin(); it != mClients.end(); ++it)
        {
            (*it)->sendBlock(block);
        }
    }

    CBlock* CChain::getCurrentBlock()
    {
        return mCurrentBlock;
    }

    CBlock* CChain::getGenesisBlock()
    {
        if(mChain.empty())
            return 0;
        return mChain[0];
    }

    void CChain::load()
    {
        mStorage->loadChain(&mChain);
        mCurrentBlock = mChain.back();
        if(mChain.size() > 1)
            nextBlock(false);
    }

    std::vector<CBlock*>* CChain::getChainPtr()
    {
        return &mChain;
    }

    size_t CChain::getBlockCount()
    {
        return mChain.size();
    }

    bool CChain::isValid()
    {
        CBlock* cur = mCurrentBlock;
        while(cur = cur->getPrevBlock())
        {
            if(!cur->isValid())
                return false;
        }
        return true;
    }

    void CChain::stop()
    {
        mRunning = false;
        /*
        if(mClients.size() != 0)
        {
            for(std::vector<Net::CClient*>::iterator it = mClients.begin(); it != mClients.end(); ++it)
            {
                (*it)->stop();
                mLog.writeLine("Waiting for client to stop...");
                while(!(*it)->isStopped())
                    sleep(1);
                mLog.writeLine("Stopped.");
            }
        }
        */
        mServer->stop();
        mStopped = true;
    }

    bool CChain::isRunning()
    {
        return !mStopped;
    }

    std::string CChain::getHostName()
    {
        return mHostName;
    }

    uint32_t CChain::getNetPort()
    {
        return mNetPort;
    }

    Net::CClient* CChain::connectNewClient(const std::string& hostname, uint32_t port, bool child)
    {
        Net::CClient* client = new Net::CClient(this, hostname, port, child);
        mClients.push_back(client);
        mLog.writeLine("Connect Client: " + hostname + ":" + std::to_string(port));
        client->start();
        return client;
    }

    std::vector<Net::CClient*>* CChain::getClientsPtr()
    {
        return &mClients;
    }

    bool CChain::isReady()
    {
        return mReady;
    }

    void CChain::insertBlock(CBlock* block)
    {
        if(mChain.empty())
            mCurrentBlock = block;
        mChain.insert(mChain.begin(), block);
    }

    void CChain::pushBlock(CBlock* block)
    {
        if(!mChain.empty())
        {
            block->setPrevBlock(mCurrentBlock);
            block->setPrevHash(mCurrentBlock->getPrevHash());
        }
        mChain.push_back(block);
        mCurrentBlock = block;
    }

    void CChain::clear()
    {
        for(std::vector<CBlock*>::iterator it = mChain.begin(); it != mChain.end(); ++it)
        {
            delete (*it);
        }
        mChain.clear();
    }

    bool CChain::hasHash(uint8_t* hash, uint32_t depth)
    {
        uint32_t c = 0;
        CBlock* cur = mCurrentBlock;
        do
        {
            if(memcmp(cur->getHash(), hash, SHA256_DIGEST_LENGTH) == 0)
                return true;
            c++;
        } while ((cur = cur->getPrevBlock()) && (depth == 0 || c <= depth));
        return false;
    }
}