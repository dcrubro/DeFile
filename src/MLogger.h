#ifndef __M_LOGGER_INCLUDED__
#define __M_LOGGER_INCLUDED__

#include <iostream>

#define LOG(msg) \
    std::cout << "\033[0m(LOG) " << __PRETTY_FUNCTION__ << ": " << msg << "\n"

#define WARN(msg) \
    std::cout << "\033[33m(WARN) \033[0m" << __PRETTY_FUNCTION__ << ": " << msg << "\n"

#define ERROR(msg) \
    std::cerr << "\033[31m(ERROR) \033[0m" << __PRETTY_FUNCTION__ << ": " << msg << "\n"

#define DBG(msg) \
    std::cerr << "\033[95m(DEBUG) \033[0m" << #msg << " - " << __PRETTY_FUNCTION__ << ": " << msg << "\n"

#endif