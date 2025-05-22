//Written by Jonas Korene Novak (aka. DcruBro), GPLv3 License

#ifndef __C_NETHELPER_INCLUDED__
#define __C_NETHELPER_INCLUDED__

#include <boost/asio.hpp>

using boost::asio::ip::tcp;

namespace DeFile::Blockchain::ANet {
    class CNetHelper {
        public:
            inline static bool isExpectedDisconnect(const boost::system::error_code& ec) {
                using boost::asio::error::operation_aborted;
                using boost::asio::error::bad_descriptor;
                using boost::asio::error::eof;

                return ec == operation_aborted || ec == bad_descriptor || ec == eof;
            }
    };
}

#endif