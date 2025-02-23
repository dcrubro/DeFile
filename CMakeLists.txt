# Minimum version of CMake required
cmake_minimum_required(VERSION 3.30)

set(PROJECT_NAME "DeFile")

# Project name and language
project(${PROJECT_NAME} VERSION 0.1 LANGUAGES CXX)

# Set debug mode
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include all source files in the src/ directory
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Add the executable by specifying all source files
add_executable(${PROJECT_NAME} ${SOURCES})

# Dependencies: OpenSSL
find_package(OpenSSL REQUIRED)

# Dependencies: secp256k1
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE ${SECP256K1_INCLUDE_DIRS})

# Link against OpenSSL and secp256k1
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto OpenSSL::SSL ${SECP256K1_LIBRARIES})

# Optionally set compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

# Optionally install the target (for example, into the /bin directory)
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
