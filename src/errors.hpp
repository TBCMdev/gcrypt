#pragma once
#include <stdexcept>
#include <expected>
#include <version>

#if !defined(__PRETTY_FUNCTION__) && !defined(__GNUC__)
    #define __PRETTY_FUNCTION__ __FUNCSIG__
#endif

#if __cplusplus >= 202302L && !defined(GCRYPT_LOG_TRACE) && (defined(GCRYPT_DEBUG) || defined(GCRYPT_TRACE))
    #define GCRYPT_ENABLE_ALL_TRACING
#endif

#if defined(GCRYPT_LOG_TRACE) || defined(GCRYPT_ENABLE_TRACE)
    #define GCRYPT_ENABLE_TRACE_LOGGING
#endif

#if defined(GCRYPT_ENABLE_ALL_TRACING) && defined(__cpp_lib_stacktrace)
    #include <stacktrace>
    #include <mutex>

    #ifndef GCRYPT_MAX_TRACE
        #define GCRYPT_MAX_TRACE 5
    #endif

    // Records the return stack trace
    #define glog(...) gcrypt::tracer.log(__VA_ARGS__)
    #define greturn(...) { glog(std::stacktrace::current()); return __VA_ARGS__; }
    namespace gcrypt
    {
        class execution_tracer
        {
            std::vector<std::stacktrace> traces;
            std::mutex mtx;
        public:
            constexpr execution_tracer()
            { traces.reserve(GCRYPT_MAX_TRACE); }
            /// @brief Returns the index of the next trace to be added, i.e. the next function you
            ///        call with trace support.
            inline std::size_t position()
            {
                std::lock_guard<std::mutex> l(mtx);
                return traces.size();
            }
            inline void log(const std::stacktrace& st)
            {
                if (traces.size() >= GCRYPT_MAX_TRACE)
                    traces.erase(traces.begin());
                std::lock_guard<std::mutex> l(mtx);
                traces.push_back(st);
            }
            inline void forget(std::size_t pos)
            {
                std::lock_guard<std::mutex> l(mtx);
                traces.erase(traces.begin() + pos);
            }
        };
        

        inline execution_tracer tracer;
    }

#elif defined(GCRYPT_ENABLE_TRACE_LOGGING) && defined(__cpp_lib_stacktrace)
    #include <stacktrace>
    #include <iostream>
    #define glog(...) std::cout << __VA_ARGS__ << '\n'
    // Prints the current stack trace, and returns the given parameters.
    #define greturn(...) { glog(std::stacktrace::current()); return __VA_ARGS__;}
#else
    #define glog(...) 
    // No debug implementation defined: therefore just returns the arguments.
    #define greturn(...) return __VA_ARGS__;
#endif

#if defined(GCRYPT_ENABLE_TRACE_LOGGING) || defined(GCRYPT_ENABLE_ALL_TRACING)

    #define GCRYPT_SCOPED_TRACE_OBJ __trace_lock
    /// @brief initializes a trace_lock object which records when and where the underlying function exits (its stack trace).
    #define init_trace(...) gcrypt::trace_lock GCRYPT_SCOPED_TRACE_OBJ
    #define gtrace(...) GCRYPT_SCOPED_TRACE_OBJ.trace(__VA_ARGS__, std::stacktrace::current())
    namespace gcrypt
    {
        /// @brief Logs the stack trace when prompted.
        class trace_lock
        {
            std::shared_ptr<std::stacktrace> st;
        public:
            ~trace_lock()
            { if (st) glog(*st); }
            constexpr trace_lock() {};

            template<typename T>
            inline T trace(T val, const std::stacktrace& _st)
            { st = std::make_shared<std::stacktrace>(_st); return val; }
        };
    }
    
#else
    /// @brief does nothing; no tracing defined.
    #define init_trace(...) 
    #define gtrace(...) __VA_ARGS__
    #define greturn(...) __VA_ARGS__
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