//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CTCPServer.h"

namespace DeFile::Blockchain::ANet {
    void CTCPServer::mStartAccept() {
        mAcceptor.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    auto client = CTCPConnection::create(std::move(socket));

                    mClients.insert(client); //Track active client

                    client->start(); //Start message handling

                    //TODO: unregister on disconnect (requires tracking logic)
                } else {
                    ERROR("Accept failed: " << ec.message());
                }

                mStartAccept(); //Continue accepting
            }
        );
    }
}