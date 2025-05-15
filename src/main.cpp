//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "Blockchain/CBlock.h"
#include "Blockchain/Storage/CStorageLocal.h"
#include "Blockchain/CWallet.h"
#include "Blockchain/Constants/CConstants.h"
#include "Blockchain/ANet/CTCPServer.h"
#include "Blockchain/ANet/CTCPClient.h"
#include <iostream>
#include <ctime>
#include <unistd.h>
#include <signal.h>
#include <map>

using namespace std;
using namespace DeFile::Blockchain;

CChain *gChain;

void interruptCallback(int sig) {
    cout << "\n";
    gChain->stop();
}

bool tobool(std::string str) {
    for (int n = 0; n < str.size(); n++)
        str[n] = std::tolower(str[n]);

    if (str == "true" || str == "t" || str == "1")
        return true;
    return false;
}

void printChain(CChain* chain) {
    CBlock *cur = chain->getCurrentBlock();
    do {
        uint64_t ts = cur->getCreatedTS();
        string tstr(std::to_string(ts));
        tstr.resize(tstr.size() - 1);
        //Note: The outputed value of the block size is the size of the block on disk (more or less), not the size in memory.
        if(cur == chain->getCurrentBlock())
            cout << "CURRENT\t" << cur->getHashStr() << "\tTimeStamp " << tstr << "\tBlock Size (Bytes) " << cur->getTotalBlockSize() << "\n";
        else
            cout << "Block\t" << cur->getHashStr() << "\tTimeStamp " << tstr << "\tBlock Size (Bytes) " << cur->getTotalBlockSize() << "\n";
    } while (cur = cur->getPrevBlock());
}

int main(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
    if (argc == 0)
    {
        cout << "Error: no binary parameter passed by system.\n";
        return 1;
    }
    string binName(argv[0]);
    if (argc == 1)
    {
        cout << "Usage:\n"
        << binName + " -hYOURHOST -cCONNECTTO -nFALSE\n\n-h\tHOSTNAME\tYour host entry point.\n-c\tHOSTNAME\tConnect to node entrypoint hostname.\n-n\ttrue | false\tIs this a new chain or not.\n\n";
        return 1;
    }

    map<string, string> params;

    for (int n = 0; n < argc; n++)
    {
        string param(argv[n]);
        if (param.size() > 2 && param[0] == '-')
        {
            string varName(param.substr(1, 1));
            params[varName] = param.substr(2);
        }
    }

    if (params.count("h") == 0)
    {
        cout << "You must specify host entrypoint for your node using -h:\nExample: " + binName + " -h127.0.0.1\n\n";
        return 1;
    }

    if (params.count("n") == 0)
    {
        if (params.count("c") == 0)
            params["n"] = "true";
        else
            params["n"] = "false";
    }
    bool isNewChain = tobool(params["n"]);

    if (!isNewChain && params.count("c") == 0)
    {
        cout << "If this is an existing chain. You must specify which node to connect to using -c:\nExample: " + binName + " -c192.168.1.10\n\n";
        return 1;
    }

    try {
        boost::asio::io_context context;
        auto server = std::make_shared<ANet::CTCPServer>(context, 9393);
        auto client = std::make_shared<ANet::CTCPClient>(context, "127.0.0.1", "9393");
        client->start();
        context.run();
    } catch (const std::exception &e) {
        std::cerr << "MAIN: Exception: " << e.what() << "\n";
    }

    //TODO: Remove the old netcode
    uint32_t hostPort = 9393, connectPort = 9393;
    std::string host(params["h"]), connectTo(params["c"]);
    size_t pos = params["h"].find(':');
    if (pos != std::string::npos)
    {
        host = params["h"].substr(0, pos);
        hostPort = (uint32_t)std::stoi(params["h"].substr(pos + 1));
    }
    pos = params["c"].find(':');
    if (pos != std::string::npos)
    {
        connectTo = params["c"].substr(0, pos);
        connectPort = (uint32_t)std::stoi(params["c"].substr(pos + 1));
    }

    Storage::E_STORAGE_TYPE storageType(Storage::EST_LOCAL);

    if (params.count("s") != 0)
    {
        if (params["s"] == "none")
            storageType = Storage::EST_NONE;
        else
            Storage::CStorageLocal::setDefaultBasePath(params["s"]);
    }

    LOG("Started " + std::string(Constants::CConstants::NODE_IDENTIFIER));

    CChain chain(host, hostPort, isNewChain, connectTo, 0, storageType, connectPort);
    gChain = &chain;

    LOG("Chain intialized!");
    LOG("Current block count: " << chain.getBlockCount());


    if (chain.isValid())
        cout << "Chain is valid!\n";
    else
    {
        cout << "INVALID CHAIN\n";
        return 1;
    }

    //We only save the chain to disk if we know it's valid.
    if (!isNewChain && params.count("c") != 0) {
        //TODO: Implement a system where only the unsaved blocks are saved. May implement from latest saved block onwards, or gap filling.
        cout << "\nSaving chain... This may take a while...\n";
        chain.save();
    }

    CBlock *current = chain.getCurrentBlock();

    //Create a new wallet for this session (temporary)
    CWallet wallet(true);
    LOG("Created Wallet.\n");
    //if (true) {}
    //std::cout << "\nPrivate Key (Length: " << wallet.getPrivKeyStr().size() << "): " << wallet.getPrivKey();
    LOG("\nWallet Address: " << wallet.getWalletAddress());
    std::cout << "\n\n";

    if (isNewChain)
    {
        //Temporary junk unverified tx to give ourselves some balance from system mint
        CTransaction testTx(
            1, //Version
            Constants::CConstants::MINT_WALLET, //SRC
            wallet.getWalletAddress(), //DEST
            100000,  //Amount
            0,  //SrcNew
            100000   //DestNew
        );
        testTx.calculateHash();
        std::string signedTx = wallet.signTransaction(&testTx); //This is a junk signature, we'll accept it temporarily
        //std::cout << signedTx << "\n";
        /*uint8_t *garbage = new uint8_t[32];
        for (uint32_t n = 0; n < 32; n++)
            garbage[n] = clock() % 255;

        cout << "Garbage generated.\n";*/

        //chain.appendToCurrentBlock(garbage, 32);

        //Note: For future reference, transactions from the system mint or system wallet don't need to be signed, since they are requested by every node.
        chain.getCurrentBlock()->addTransaction(signedTx);
        //delete[] garbage;

        cout << "TX appended to current block.\n";

        chain.nextBlock();

        cout << "Next block mined.\n";

        cout << "Current Hash: " << chain.getCurrentBlock()->getPrevBlock()->getHashStr() << "\nNonce: " << chain.getCurrentBlock()->getNonce() << "\n";

        int blocksNumToGen = 128;

        for (int i = 0; i < blocksNumToGen; i++) {
            uint32_t garbageSize = 0xFFFF; //Roughly 65k bytes, vectors luckily auto free
            std::vector<uint8_t> garbage(garbageSize);
            for (uint32_t n = 0; n < garbageSize; n++)
                garbage[n] = clock() % 255;

            cout << "Garbage generated.\n";
            CBlock* cB = chain.getCurrentBlock();
            cout << &cB << "\n";
            chain.getCurrentBlock()->appendDynamicData(garbage);
            //chain.appendDynamicDataToCurrentBlock(garbage); //Pass a copy of the data. TODO: Make this better and save in chunks to preserve memory.
            cout << "Garbage appended to current block dynamic data.\n";
            cB = chain.getCurrentBlock();
            cout << &cB << "\n";
            chain.getStoragePtr()->saveBlockDynamicData(chain.getCurrentBlock(), true, true);
            cB = chain.getCurrentBlock();
            cout << &cB << "\n";
            chain.nextBlock(true, true);

            cout << "Next block mined.\n";

            cout << "Previous Hash: " << chain.getCurrentBlock()->getPrevBlock()->getHashStr() << "\nNonce: " << chain.getCurrentBlock()->getNonce() << "\n";
        }

        cout << "Garbage appended to current block.\n";

        chain.nextBlock();

        cout << "Next block mined.\n";

        cout << "Previous Hash: " << chain.getCurrentBlock()->getPrevBlock()->getHashStr() << "\nNonce: " << chain.getCurrentBlock()->getNonce() << "\n";
    } else {
        /*uint8_t* garbage = new uint8_t[32];
        for(uint32_t n = 0; n < 32; n++)
            garbage[n] = clock() % 255;
        chain.appendToCurrentBlock(garbage, 32);
        delete[] garbage;

        cout << "Garbage appended to current block.\n";

        chain.nextBlock();

        cout << "Next block mined.\n";

        cout << "Previous Hash: " << chain.getCurrentBlock()->getPrevBlock()->getHashStr() << "\nNonce: " << chain.getCurrentBlock()->getNonce() << "\n";
        */    
    }
    cout << "Current block count: " << chain.getBlockCount() << "\n";

    cout << "\n"
    << "## BLOCK LIST (Descending)"
    << "\n";

    printChain(&chain);

    // Interrupt Signal
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = interruptCallback;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);
    sigaction(SIGQUIT, &sigIntHandler, NULL);

    CBlock* printedBlock = chain.getCurrentBlock();

    while (chain.isRunning()) {

        usleep(5000);
        if(printedBlock != chain.getCurrentBlock())
        {
            printChain(&chain);
            printedBlock = chain.getCurrentBlock();
        }
    }

    cout << "\nExit.\n";

    return 0;
}
