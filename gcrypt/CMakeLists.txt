cmake_minimum_required(VERSION 3.15)

project(gcrypt C CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# 1. Define MLK_CONFIG_PARAMETER_SET BEFORE FetchContent runs
add_compile_definitions(MLK_CONFIG_PARAMETER_SET=1024)

# --- Fetch mlkem-native repository ---
FetchContent_Declare(
    mlkem_native
    GIT_REPOSITORY https://github.com/pq-code-package/mlkem-native.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(mlkem_native)

# Automatically locate mlkem_native.h subfolder path
find_path(MLKEM_NATIVE_INCLUDE_DIR
    NAMES mlkem_native.h
    PATHS
        "${mlkem_native_SOURCE_DIR}"
        "${mlkem_native_BINARY_DIR}"
    PATH_SUFFIXES
        mlkem
        mlkem/native
        mlkem_native
        src
        c
        native
    NO_DEFAULT_PATH
)

# --- Collect all C/C++ source files from /src ---
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

# Entry point wrapper for Android JNI interface
set(JNI_ENTRY_POINT "${CMAKE_CURRENT_SOURCE_DIR}/jnib.cpp")

# --- Platform-Specific System Libraries ---
set(PLATFORM_LIBS "")

if(ANDROID)
    find_library(LOG_LIB log)
    if(LOG_LIB)
        list(APPEND PLATFORM_LIBS ${LOG_LIB})
    endif()
else()
    find_package(Threads REQUIRED)
    list(APPEND PLATFORM_LIBS Threads::Threads ${CMAKE_DL_LIBS})

    if(WIN32)
        list(APPEND PLATFORM_LIBS ws2_32 crypt32 advapi32 user32)
    endif()
endif()

# --- OpenSSL Setup ---
if(ANDROID_ABI)
    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl/${ANDROID_ABI}")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl")
    set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/openssl")
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()

find_package(OpenSSL REQUIRED)

# --- Libsodium Setup ---
if(ANDROID_ABI)
    set(SODIUM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/libsodium/${ANDROID_ABI}")
else()
    set(SODIUM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/libsodium")
endif()

if(EXISTS "${SODIUM_DIR}/include")
    add_library(libsodium STATIC IMPORTED)

    if(WIN32 AND MSVC)
        set(SODIUM_LIB_PATH "${SODIUM_DIR}/lib/libsodium.lib")
    else()
        set(SODIUM_LIB_PATH "${SODIUM_DIR}/lib/libsodium.a")
    endif()

    set_target_properties(libsodium PROPERTIES
        IMPORTED_LOCATION "${SODIUM_LIB_PATH}"
        INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_DIR}/include"
        INTERFACE_COMPILE_DEFINITIONS "SODIUM_STATIC"
    )
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(SODIUM libsodium REQUIRED IMPORTED_TARGET)
        add_library(libsodium ALIAS PkgConfig::SODIUM)
    else()
        find_library(SODIUM_LIB NAMES sodium libsodium REQUIRED)
        find_path(SODIUM_INCLUDE_DIR NAMES sodium.h REQUIRED)
        add_library(libsodium UNKNOWN IMPORTED)
        set_target_properties(libsodium PROPERTIES
            IMPORTED_LOCATION "${SODIUM_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
        )
    endif()
endif()

# --- Target Definition ---
if(ANDROID)
    add_library(gcrypt SHARED
        ${JNI_ENTRY_POINT}
        ${CORE_SOURCES}
    )
else()
    add_library(gcrypt STATIC
        ${CORE_SOURCES}
    )
endif()

# --- Include Directories ---
target_include_directories(gcrypt PRIVATE 
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${MLKEM_NATIVE_INCLUDE_DIR}"
    "${mlkem_native_SOURCE_DIR}"
    "${mlkem_native_BINARY_DIR}"
)

# Desktop Fallback JNI Headers
if(NOT ANDROID)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/android/include")
        target_include_directories(gcrypt PRIVATE
            "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/android/include"
        )
    endif()
endif()

# --- Target Linking ---
target_link_libraries(gcrypt PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto 
    libsodium 
    mlkem_native 
    ${PLATFORM_LIBS}
)