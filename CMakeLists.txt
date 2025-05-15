# Minimum version of CMake required
cmake_minimum_required(VERSION 3.30)

set(PROJECT_NAME "DeFile")

# Project name and language
project(${PROJECT_NAME} VERSION 0.1 LANGUAGES C CXX)

# Set debug mode
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Target generic x86
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=x86-64 -mtune=generic -O2")

# Include all source files in the src/ directory
#file(GLOB_RECURSE SOURCES "src/*.cpp")

#add_library(${PROJECT_NAME}LIB STATIC 
#    src/Blockchain/CLog.cpp
#    src/Blockchain/CTransaction.cpp
#    src/Blockchain/CWallet.cpp
#    src/Blockchain/CBlock.cpp
#    src/Blockchain/Storage/Storage.cpp
#    src/Blockchain/Storage/CStorageLocal.cpp
#    src/Blockchain/Net/INet.cpp
#    src/Blockchain/Net/CClient.cpp
#    src/Blockchain/Net/CServer.cpp
#    src/Blockchain/CChain.cpp
#    src/main.cpp
#)

set(SOURCES
    src/Blockchain/CLog.cpp
    src/Blockchain/CTransaction.cpp
    src/Blockchain/CWallet.cpp
    src/Blockchain/CBlock.cpp
    src/Blockchain/Storage/Storage.cpp
    src/Blockchain/Storage/CStorageLocal.cpp
    src/Blockchain/Net/INet.cpp
    src/Blockchain/Net/CClient.cpp
    src/Blockchain/Net/CServer.cpp
    src/Blockchain/ANet/CTCPServer.cpp
    src/Blockchain/ANet/CMessageHandler.cpp
    src/Blockchain/CChain.cpp
    src/main.cpp
)

add_subdirectory(src/blake3/c)

# Add the executable by specifying all source files
add_executable(${PROJECT_NAME} ${SOURCES})

# Dependencies: OpenSSL
find_package(OpenSSL REQUIRED)

# Dependencies: secp256k1
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE ${SECP256K1_INCLUDE_DIRS} src/blake3/c src/asio/include)

# Link against OpenSSL and secp256k1
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto OpenSSL::SSL ${SECP256K1_LIBRARIES} blake3)

# Optionally set compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

# Optionally install the target (for example, into the /bin directory)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
