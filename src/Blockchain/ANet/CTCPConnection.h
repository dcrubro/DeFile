//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TCPCONNECTION_INCLUDED__
#define __C_TCPCONNECTION_INCLUDED__

#include <iostream>
#include <memory>
#include <string>
#include <ctime>
#include <cstdint>
#include <boost/asio.hpp>
#include "EMessageType.h"
#include "CMessageHandler.h"
#include "../CTimeUtils.h"
#include "../Constants/CConstants.h"

using boost::asio::ip::tcp;

namespace DeFile::Blockchain::ANet {
    class CTCPConnection : public std::enable_shared_from_this<CTCPConnection> {
        public:
            using pointer = std::shared_ptr<CTCPConnection>;

            static pointer create(boost::asio::ip::tcp::socket socket) {
                return pointer(new CTCPConnection(std::move(socket)));
            }

            void start() {
                mHandler->onMessage([this](EMessageType type, const std::string& data) {
                    handleMessage(type, data);
                });
                mHandler->start();
                
                //mHandler->sendMessage(EMessageType::HELLO, "Welcome, client!");
            }
        
            void sendMessage(EMessageType type, const std::string& data = "") {
                mHandler->sendMessage(type, data);
            }
        
        private:
            CTCPConnection(boost::asio::ip::tcp::socket socket)
                : mHandler(std::make_shared<CMessageHandler>(std::move(socket))) {}

            void handleMessage(EMessageType type, const std::string& data) {
                switch (type) {
                    case EMessageType::HELLO:
                        LOG("Server received HELLO: " << data << " FROM " + mHandler->socket().remote_endpoint().address().to_string());
                        mHandler->sendMessage(EMessageType::HELLO, "Hello, I am " + std::string(Constants::CConstants::NODE_IDENTIFIER));
                        break;
                    case EMessageType::TXTMSG:
                        LOG("Server received text: " << data);
                        break;
                    default:
                        LOG("Server received unknown message type.");
                        break;
                }
            }
        
            std::shared_ptr<CMessageHandler> mHandler;
    };
}

#endif