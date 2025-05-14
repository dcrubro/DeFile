//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TCPSERVER_INCLUDED__
#define __C_TCPSERVER_INCLUDED__

#include "CTCPConnection.h"
#include <unordered_set>

namespace DeFile::Blockchain::ANet {
    class CTCPServer {
        public:
            CTCPServer(boost::asio::io_context &ioContext, uint16_t port)
                : mIoContext(ioContext), mAcceptor(ioContext, tcp::endpoint(tcp::v4(), port))
            {
                mStartAccept();
            }

        private:
            void mStartAccept();

            boost::asio::io_context &mIoContext;
            tcp::acceptor mAcceptor;
            std::unordered_set<CTCPConnection::pointer> mClients;
            
    };
}

#endif