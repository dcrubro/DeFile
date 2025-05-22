//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CTCPServer.h"
#include "CNetHelper.h"

namespace DeFile::Blockchain::ANet {
    void CTCPServer::mStartAccept() {
        mAcceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!CNetHelper::isExpectedDisconnect(ec)) {
                    auto client = CTCPConnection::create(std::move(socket),
                        [this](std::shared_ptr<CTCPConnection> c) {
                            mClients.erase(c);
                            LOG("Client removed.");
                        });
                    
                    mClients.insert(client);
                    client->start();
                } else {
                    ERROR("Accept failed: " << ec.message());
                }

                mStartAccept(); // Accept next
            }
        );
    }
}