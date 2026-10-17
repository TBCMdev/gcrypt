#pragma once
#include <stdexcept>
#include <expected>

#if !defined(__PRETTY_FUNCTION__) && !defined(__GNUC__)
    #define __PRETTY_FUNCTION__ __FUNCSIG__
#endif

namespace gcrypt
{
#define GCRYPT_NOT_IMPLEMENTED(warn) throw gcrypt::not_implemented(warn);
    class not_implemented : public std::logic_error
    {
    public:
        not_implemented() : std::logic_error("Function not yet implemented") { };
        not_implemented(const std::string& s) : std::logic_error(s) { };
    };
    class convert_exception : public std::logic_error
    {
    public:
        convert_exception() : std::logic_error("Conversion failed.")
        { };

        
        convert_exception(const std::string& err) : std::logic_error(err)
                                        { };
    };
#define _ERR_STR "Conversion failed with execution: {}"

    inline convert_exception convert_failed() { return convert_exception(); };
    template<typename _From, typename _To>
    inline convert_exception convert_failed() { return convert_exception(std::format(_ERR_STR, __PRETTY_FUNCTION__)); };
    template<typename _From, typename _To>
    inline convert_exception convert_failed(const std::string& err) { return convert_exception(std::format(_ERR_STR " with error: '{}'", __PRETTY_FUNCTION__, err)); };
    template<typename _From, typename _To>
    inline std::unexpected<convert_exception> convert_error(const std::string& err) { return std::unexpected(convert_failed<_From, _To>(err)); };
    template<typename _From, typename _To>
    inline std::unexpected<convert_exception> convert_error() { return std::unexpected(convert_failed<_From, _To>()); };

#undef _ERR_STR

}