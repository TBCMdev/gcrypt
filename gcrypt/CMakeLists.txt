cmake_minimum_required(VERSION 3.15)
project(MyGeckoProject CXX)

set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl")
set(OPENSSL_USE_STATIC_LIBS TRUE) # Set to TRUE if you built static libs

find_package(OpenSSL REQUIRED)

add_executable(my_app main.cpp)

target_link_libraries(my_app PRIVATE OpenSSL::SSL OpenSSL::Crypto)