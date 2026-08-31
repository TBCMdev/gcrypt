cmake_minimum_required(VERSION 3.15)
project(MyGeckoProject CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Threads REQUIRED)

# --- 1. Collect all source and header files from /src ---
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h"
)

# --- 2. Dependencies ---
set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl")
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

set(SODIUM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/libsodium")
set(SODIUM_INCLUDE_DIR "${SODIUM_DIR}/include")

if(WIN32)
    set(SODIUM_LIBRARY "${SODIUM_DIR}/lib/libsodium.lib")
else()
    set(SODIUM_LIBRARY "${SODIUM_DIR}/lib/libsodium.a")
endif()

add_library(libsodium STATIC IMPORTED)
set_target_properties(libsodium PROPERTIES
    IMPORTED_LOCATION "${SODIUM_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
)

# --- 3. Build Executable using all collected sources ---
add_executable(gcrypt_test ${SOURCES})

# Include your project's header directory so #include "gen.hpp" works everywhere
target_include_directories(gcrypt_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(gcrypt_test PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    libsodium 
    Threads::Threads
    ${CMAKE_DL_LIBS}
)