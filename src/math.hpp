#pragma once


#include "sodium.h"
#include "protocol.hpp"


#include <array>

namespace gcrypt::math
{
    using key32 = std::array<uint8_t, 32>;

}