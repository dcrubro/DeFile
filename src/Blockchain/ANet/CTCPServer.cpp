//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CTCPServer.h"

namespace DeFile::Blockchain::ANet {
    void CTCPServer::mStartAccept() {
        auto newCon = CTCPConnection::create(mIoContext);
        auto self = this;

        mAcceptor.async_accept(newCon->socket(),
            [this, newCon](boost::system::error_code ec) {
                if (!ec) {
                    mClients.insert(newCon);

                    // Pass a lambda to remove this client when done
                    newCon->start([this](CTCPConnection::pointer conn) {
                        mClients.erase(conn);
                    });
                }

                mStartAccept(); //Accept next connection
            });
    }
}