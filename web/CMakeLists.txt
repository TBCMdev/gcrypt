# these are web only additions, should be only reached when building with Emscripten.

target_sources(gcrypt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/StorageManager.cpp
)

target_include_directories(gcrypt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
)