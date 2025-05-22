//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#include "CMessageHandler.h"

namespace DeFile::Blockchain::ANet {
    void CMessageHandler::start() {
        mReadHeader();
    }

    void CMessageHandler::sendMessage(EMessageType type, const std::string &payload) {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(type));
        uint16_t length = payload.size();

        data.push_back(length >> 8);
        data.push_back(length & 0xFF);

        data.insert(data.end(), payload.begin(), payload.end());
        auto self = shared_from_this();
        boost::asio::async_write(mSocket, boost::asio::buffer(data),
            [self](boost::system::error_code ec, std::size_t) {
                if (ec) {
                    ERROR("Send failed: " << ec.message());
                }
            }
        );
    }

    void CMessageHandler::onMessage(std::function<void(EMessageType, std::string)> callback) {
        mOnMessage = std::move(callback);
    }

    void CMessageHandler::mReadHeader() {
        auto self = shared_from_this();
        boost::asio::async_read(mSocket, boost::asio::buffer(mHeader),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (!CNetHelper::isExpectedDisconnect(ec)) {
                    mCurrentType = static_cast<EMessageType>(mHeader[0]);
                    uint16_t len = (mHeader[1] << 8) | mHeader[2];
                    mReadBody(len);
                } else {
                    ERROR("Header read failed: " << ec.message());
                }
            }
        );
    }

    void CMessageHandler::mReadBody(uint16_t length) {
        auto self = shared_from_this();
        mBody.resize(length);

        boost::asio::async_read(mSocket, boost::asio::buffer(mBody),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (!CNetHelper::isExpectedDisconnect(ec)) {
                    std::string payload(mBody.begin(), mBody.end());
                    if (mOnMessage) {
                        mOnMessage(mCurrentType, payload);
                    }
                    mReadHeader(); // Keep listening
                } else {
                    ERROR("Body read failed: " << ec.message());

                    if (mOnDisconnect) {
                        mOnDisconnect(ec);
                    }
                }
            }
        );
    }
}