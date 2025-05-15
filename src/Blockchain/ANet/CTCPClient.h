//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TCPCLIENT_INCLUDED__
#define __C_TCPCLIENT_INCLUDED__

#include "../../MLogger.h"
#include "CMessageHandler.h"
#include <iostream>
#include <memory>
#include <array>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

namespace DeFile::Blockchain::ANet {
    class CTCPClient : public std::enable_shared_from_this<CTCPClient> {
        public:
            CTCPClient(boost::asio::io_context &ioContext, 
                       const std::string &host,
                       const std::string &port)
                : mResolver(ioContext), mSocket(ioContext)
            {
                mHost = host;
                mPort = port;
            }

            void start() {
                auto self = shared_from_this();
                mResolver.async_resolve(mHost, mPort,
                    [this, self](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                        if (!ec) {
                            boost::asio::async_connect(mSocket, endpoints,
                                [this, self](boost::system::error_code ec, const tcp::endpoint&) {
                                    if (!ec) {
                                        LOG("Client connected.");
                                        mHandler = std::make_shared<CMessageHandler>(std::move(mSocket));
                                        mHandler->onMessage([this](EMessageType type, const std::string& data) {
                                            mHandleMessage(type, data);
                                        });
                                        mHandler->start();
                                    
                                        // Example: say hello
                                        mHandler->sendMessage(EMessageType::HELLO, "Hello, I am " + std::string(Constants::CConstants::NODE_IDENTIFIER));
                                    } else {
                                        ERROR("Client connect failed: " << ec.message());
                                    }
                                });
                        } else {
                            ERROR("Client resolve failed: " << ec.message());
                        }
                    });
            }

            void sendMessage(EMessageType type, const std::string& data = "") {
                if (mHandler) mHandler->sendMessage(type, data);
            }

        private:
            void mHandleMessage(EMessageType type, const std::string& data) {
                using namespace DeFile::Blockchain::ANet;
                switch (type) {
                    case EMessageType::HELLO:
                        LOG("Client received HELLO: " << data << "FROM " + mHandler->socket().remote_endpoint().address().to_string());
                        mHandler->sendMessage(EMessageType::TXTMSG, "Test msg.");
                        break;
                    case EMessageType::TXTMSG:
                        LOG("Client received text: " << data);
                        break;
                    default:
                        LOG("Client received unknown message type.");
                        break;
                }
            }
            
            tcp::resolver mResolver;
            tcp::socket mSocket;
            std::shared_ptr<CMessageHandler> mHandler;
            std::string mHost, mPort;
    };
}

#endif
