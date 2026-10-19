#pragma once
#include <stdexcept>
#include <expected>

#if !defined(__PRETTY_FUNCTION__) && !defined(__GNUC__)
    #define __PRETTY_FUNCTION__ __FUNCSIG__
#endif
// todo remove
#define GCRYPT_DEBUG

#if __cplusplus >= 202302L && !defined(GCRYPT_LOG_TRACE) && (defined(GCRYPT_DEBUG) || defined(GCRYPT_TRACE))
    #define GCRYPT_ENABLE_ALL_TRACING
#endif

#if defined(GCRYPT_LOG_TRACE) || defined(GCRYPT_ENABLE_TRACE)
    #define GCRYPT_ENABLE_TRACE_LOGGING
#endif

#ifdef GCRYPT_ENABLE_ALL_TRACING
    #include <stacktrace>
    #include <mutex>

    #ifndef GCRYPT_MAX_TRACE
        #define GCRYPT_MAX_TRACE 5
    #endif

    // Records the return stack trace
    #define algreturn(...) { gcrypt::tracer.log(std::stacktrace::current()); return __VA_ARGS__; }
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

#elif defined(GCRYPT_ENABLE_TRACE_LOGGING)
    #include <stacktrace>
    // Prints the current stack trace, and returns the given parameters.
    #define algreturn(...) { std::cout << std::stacktrace::current() << std::endl; return __VA_ARGS__;}
#else
    // No debug implementation defined: therefore just returns the arguments.
    #define algreturn(...) return __VA_ARGS__;
#endif


#if defined(GCRYPT_ENABLE_TRACE_LOGGING) || defined(GCRYPT_ENABLE_ALL_TRACING)

    #define GCRYPT_SCOPED_TRACE_OBJ __trace_lock
    /// @brief initializes a trace_lock object which records when and where the underlying function exits (its stack trace).
    #define init_trace(...) gcrypt::trace_lock GCRYPT_SCOPED_TRACE_OBJ
    /// @brief disables the tracing of the trace_lock object defined from initializing trace functionality.
    #define disable_trace(...) GCRYPT_SCOPED_TRACE_OBJ.successful()
    /// @brief enables the tracing of the trace_lock object defined from initializing trace functionality.
    #define enable_trace(...) GCRYPT_SCOPED_TRACE_OBJ.unsuccessful()

    namespace gcrypt
    {
        /// @brief Logs the stack trace when destructed, if the trace is unsuccessful.
        class trace_lock
        {
            bool _success = false;
        public:
            ~trace_lock()
            { if (!_success) algreturn(); }
            constexpr trace_lock() {};

            /// @brief marks the trace as a non error, therefore no stack trace is logged.
            constexpr inline void successful()
            { _success = true; }
            /// @brief marks the trace as an error, meaning on destruction the trace will be logged.
            constexpr inline void unsuccessful()
            { _success = false; }
        };
    }
    
#else
    /// @brief does nothing; no tracing defined.
    #define init_trace(...)
    /// @brief does nothing; no tracing defined.
    #define disable_trace(...)
    /// @brief does nothing; no tracing defined.
    #define enable_trace(...)
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