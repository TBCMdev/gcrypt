#pragma once
#include <stdexcept>

namespace gcrypt
{
#define GCRYPT_NOT_IMPLEMENTED(warn) throw gcrypt::not_implemented(warn);

    class not_implemented : public std::logic_error
    {
    public:
        not_implemented() : std::logic_error("Function not yet implemented") { };
        not_implemented(const std::string& s) : std::logic_error(s) { };
    };
}