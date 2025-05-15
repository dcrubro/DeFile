//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_MESSAGEHANDLER_INCLUDED__
#define __C_MESSAGEHANDLER_INCLUDED__

#include "EMessageType.h"
#include "../../MLogger.h"
#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <functional>

using tcp = boost::asio::ip::tcp;

namespace DeFile::Blockchain::ANet {
    class CMessageHandler : public std::enable_shared_from_this<CMessageHandler> {
        public:
            CMessageHandler(tcp::socket socket)
                : mSocket(std::move(socket)) {}
            
            boost::asio::ip::tcp::socket &socket() { return mSocket; }

            void start();
            void sendMessage(EMessageType type, const std::string &payload = "");
            void onMessage(std::function<void(EMessageType, std::string)> callback);
        
        private:
            void mReadHeader();
            void mReadBody(uint16_t length);

            tcp::socket mSocket;
            EMessageType mCurrentType = EMessageType::UNKNOWN;
            std::array<uint8_t, 3> mHeader{}; // [type][lenHigh][lenLow]
            std::vector<uint8_t> mBody;
            std::function<void(EMessageType, std::string)> mOnMessage;
    };
}

#endif