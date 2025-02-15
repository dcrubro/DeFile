# Minimum version of CMake required
cmake_minimum_required(VERSION 3.30)

set(PROJECT_NAME "DeFile")

# Project name and language
project(${PROJECT_NAME} VERSION 0.1 LANGUAGES CXX)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include all source files in the src/ directory
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Add the executable by specifying all source files
add_executable(${PROJECT_NAME} ${SOURCES})

# Dependencies
find_package(ssl)
find_package(crypto)
target_link_libraries(${PROJECT_NAME} ssl crypto)

# Optionally set compiler flags (optional)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

# Optionally set the version info for the target
set_target_properties(${PROJECT_NAME} PROPERTIES VERSION ${PROJECT_VERSION})

# Optionally install the target (for example, into the /bin directory)
install(TARGETS ${PROJECT_NAME} DESTINATION build)
