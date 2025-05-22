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

            static pointer create(
                boost::asio::ip::tcp::socket socket,
                std::function<void(pointer)> onDisconnect)
            {
                auto conn = pointer(new CTCPConnection(std::move(socket)));
                conn->mOnDisconnect = std::move(onDisconnect);
                return conn;
            }

            void start() {
                mHandler->onMessage([this](EMessageType type, const std::string& data) {
                    handleMessage(type, data);
                });

                mHandler->onDisconnect([this](const boost::system::error_code& ec) {
                    LOG("[Server] Client disconnected (error): " << ec.message());
                    disconnect();
                });

                mHandler->start();
                
                //mHandler->sendMessage(EMessageType::HELLO, "Welcome, client!");
            }
        
            void sendMessage(EMessageType type, const std::string& data = "") {
                mHandler->sendMessage(type, data);
            }

            void setDisconnectCallback(std::function<void(std::shared_ptr<CTCPConnection>)> cb) {
                mOnDisconnect = std::move(cb);
            }

            void disconnect() {
                std::string ip = mHandler->socket().remote_endpoint().address().to_string();

                boost::system::error_code ec;
                mHandler->socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
                mHandler->socket().close(ec);

                LOG("[Server] Closed connection to " << ip);

                if (mOnDisconnect) {
                    mOnDisconnect(shared_from_this());
                }
            }
        
        private:
            CTCPConnection(boost::asio::ip::tcp::socket socket)
                : mHandler(std::make_shared<CMessageHandler>(std::move(socket))) {}

            void handleMessage(EMessageType type, const std::string& data) {
                std::string reqAddr = mHandler->socket().remote_endpoint().address().to_string();
                switch (type) {
                    case EMessageType::HELLO:
                        LOG("Server received HELLO: " << data << " FROM " + reqAddr);
                        mHandler->sendMessage(EMessageType::HELLO, "Hello, I am " + std::string(Constants::CConstants::NODE_IDENTIFIER));
                        break;
                    case EMessageType::TXTMSG:
                        LOG("Server received text: " << data);
                        break;
                    case EMessageType::PING:
                        mHandler->sendMessage(EMessageType::PONG, "");
                        break;
                    case EMessageType::REQSYN:
                        LOG(reqAddr + " is requesting sync from block " << data);
                        break;
                    case EMessageType::DISCONNECT:
                        LOG("Server received disconnect request from " << reqAddr);
                        disconnect();
                        break;
                    default:
                        LOG("Server received unknown message type.");
                        break;
                }
            }
        
            std::shared_ptr<CMessageHandler> mHandler;
            std::function<void(std::shared_ptr<CTCPConnection>)> mOnDisconnect;
    };
}

#endif