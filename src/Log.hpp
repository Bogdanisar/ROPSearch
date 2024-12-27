#ifndef LOG_H
#define LOG_H

#include <sstream>
#include <iostream>


class Log {
    public:

    enum class Level {
        Error   = 1<<0,
        Warn    = 1<<1,
        Info    = 1<<2,
        Verbose = 1<<3,
        Debug   = 1<<4,
    };

    static Level ProgramLogLevel;
};


/**
 * Converts a C++ expression/object into a temporary C-string (if a conversion to std::string exists).
 * Beware: A temporary object gets deallocated right after the full expression in which it is used.
 * Use this macro along with "%s" format specifiers for the format string Log functions.
 * @note
 * Correct usage: `LogInfo("i = %i; obj = %s", i, CSTR(obj));`
 * @warning
 * Incorrect usage (Undefined behavior): `char *ptr = CSTR(obj); func(ptr);`
 */
#define CSTR(obj) (((std::stringstream&)(std::stringstream() << (obj))).str().c_str())


#define LogBase(fmt, ...) printf(fmt "\n", ##__VA_ARGS__)

#define LogMaybe(level, fmt, ...) \
    do { \
        if (level <= Log::ProgramLogLevel) { \
            LogBase(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LogError(fmt, ...) LogMaybe(Log::Level::Error, fmt, ##__VA_ARGS__)
#define LogWarn(fmt, ...) LogMaybe(Log::Level::Warn, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...) LogMaybe(Log::Level::Info, fmt, ##__VA_ARGS__)
#define LogVerbose(fmt, ...) LogMaybe(Log::Level::Verbose, fmt, ##__VA_ARGS__)
#define LogDebug(fmt, ...) LogMaybe(Log::Level::Debug, fmt, ##__VA_ARGS__)


#endif // LOG_H
