cmake_minimum_required(VERSION 3.20)

project(gcrypt C CXX)

include(FetchContent)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Optional
add_compile_definitions(GCRYPT_LOG_TRACE)
add_compile_options(-g)

# mlkem-native
FetchContent_Declare(
    mlkem_native
    GIT_REPOSITORY https://github.com/pq-code-package/mlkem-native.git
    GIT_TAG        main   # TODO: pin to a release tag or commit hash
)
FetchContent_MakeAvailable(mlkem_native)

add_library(mlkem_native STATIC
    ${mlkem_native_SOURCE_DIR}/mlkem/mlkem_native.c
)

# Only needed if you enable the native backends (x86_64 / aarch64 asm).
# Harmless otherwise, but uncomment when you set MLK_CONFIG_USE_NATIVE_BACKEND_*.
# target_sources(mlkem_native PRIVATE
#     ${mlkem_native_SOURCE_DIR}/mlkem/mlkem_native.S
# )

target_include_directories(mlkem_native PUBLIC
    ${mlkem_native_SOURCE_DIR}/mlkem
)

target_compile_definitions(mlkem_native PUBLIC
    MLK_CONFIG_PARAMETER_SET=1024
    MLK_CONFIG_NAMESPACE_PREFIX=mlkimpl
)

# Platform libs
set(PLATFORM_LIBS "")

find_package(Threads REQUIRED)
list(APPEND PLATFORM_LIBS Threads::Threads ${CMAKE_DL_LIBS})

if(WIN32)
    list(APPEND PLATFORM_LIBS ws2_32 crypt32 advapi32 user32)
endif()

# libsodium (bundled if present, otherwise system)
set(SODIUM_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/libsodium")

if(EXISTS "${SODIUM_DIR}/include")
    add_library(libsodium STATIC IMPORTED)

    if(WIN32 AND MSVC)
        set(SODIUM_LIB_PATH "${SODIUM_DIR}/lib/libsodium.lib")
    else()
        set(SODIUM_LIB_PATH "${SODIUM_DIR}/lib/libsodium.a")
    endif()

    set_target_properties(libsodium PROPERTIES
        IMPORTED_LOCATION             "${SODIUM_LIB_PATH}"
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
            IMPORTED_LOCATION             "${SODIUM_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${SODIUM_INCLUDE_DIR}"
        )
    endif()
endif()

# gcrypt library
file(GLOB_RECURSE CORE_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
)

add_library(gcrypt STATIC ${CORE_SOURCES})

option(GCRYPT_NOSTORE "Disable storage capabilities" OFF)
if(GCRYPT_NOSTORE)
    target_compile_definitions(gcrypt PUBLIC GCRYPT_NOSTORE)
endif()

target_include_directories(gcrypt PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/android/include")
    target_include_directories(gcrypt PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/dependencies/android/include"
    )
endif()

# PUBLIC: anything linking gcrypt also gets libsodium + mlkem_native
# (include dirs, compile definitions and link flags propagate automatically).
target_link_libraries(gcrypt PUBLIC
    libsodium
    mlkem_native
    stdc++exp
    ${PLATFORM_LIBS}
)

add_executable(testbin tests/keys.cpp)
target_link_libraries(testbin PRIVATE gcrypt stdc++exp)