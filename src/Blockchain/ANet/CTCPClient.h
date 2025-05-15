//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_TCPCLIENT_INCLUDED__
#define __C_TCPCLIENT_INCLUDED__

#include "../../MLogger.h"
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
                mConnect(host, port);
            }

        private:
            void mConnect(const std::string& host, const std::string& port) {
                auto self = shared_from_this();

                mResolver.async_resolve(host, port,
                    [this, self](boost::system::error_code ec, tcp::resolver::results_type endpoints) {
                        if (!ec) {
                            boost::asio::async_connect(mSocket, endpoints,
                                [this, self](boost::system::error_code ec, const tcp::endpoint&) {
                                    if (!ec) {
                                        read();
                                    } else {
                                        ERROR("Connect failed: " << ec.message());
                                    }
                                });
                        } else {
                            ERROR("Resolve failed: " << ec.message());
                        }
                    });
            }

            void read() {
                auto self = shared_from_this();
                mSocket.async_read_some(boost::asio::buffer(mBuffer),
                    [this, self](boost::system::error_code ec, std::size_t length) {
                        if (!ec) {
                            LOG("Received: " << std::string(mBuffer.data(), length));
                        } else {
                            ERROR("Read failed: " << ec.message());
                        }
                    });
            }
        
            tcp::resolver mResolver;
            tcp::socket mSocket;
            std::array<char, 1024> mBuffer;
    };
}

#endif
