//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TCPCONNECTION_INCLUDED__
#define __C_TCPCONNECTION_INCLUDED__

#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <cstdint>
#include <boost/asio.hpp>
#include "../CTimeUtils.h"

using boost::asio::ip::tcp;

namespace DeFile::Blockchain::ANet {
    class CTCPConnection : public std::enable_shared_from_this<CTCPConnection> {
        public:
            using pointer = std::shared_ptr<CTCPConnection>;

            static pointer create(boost::asio::io_context &ioContext) {
                return pointer(new CTCPConnection(ioContext));
            }

            tcp::socket &socket() {
                return mSocket;
            }

            void start(std::function<void(pointer)> onDisconnect) {
                mMessage = mMakeDaytimeString();
                auto self = shared_from_this();

                boost::asio::async_write(mSocket, boost::asio::buffer(mMessage),
                    [self, onDisconnect](boost::system::error_code ec, std::size_t /*length*/) {
                        if (!ec) {
                            // Connection automatically closes when the shared_ptr goes out of scope
                        }

                        onDisconnect(self);
                    });
            }
        
        private:
            CTCPConnection(boost::asio::io_context &ioContext)
                : mSocket(ioContext) {}
            
            std::string mMakeDaytimeString() {
                std::time_t now = std::time(nullptr);
                return std::ctime(&now);
            }

            tcp::socket mSocket;
            std::string mMessage;
    };
}

#endif