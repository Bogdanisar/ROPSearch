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


#define LogBase(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define LogMaybe(level, flush, fmt, ...) \
    do { \
        if (level <= Log::ProgramLogLevel) { \
            LogBase(fmt, ##__VA_ARGS__); \
            if (flush) { \
                fflush(stdout); \
            } \
        } \
    } while (0)

#define LogError(fmt, ...) LogMaybe(Log::Level::Error, true, fmt "\n", ##__VA_ARGS__)
#define LogWarn(fmt, ...) LogMaybe(Log::Level::Warn, false, fmt "\n", ##__VA_ARGS__)
#define LogInfo(fmt, ...) LogMaybe(Log::Level::Info, false, fmt "\n", ##__VA_ARGS__)
#define LogVerbose(fmt, ...) LogMaybe(Log::Level::Verbose, false, fmt "\n", ##__VA_ARGS__)
#define LogDebug(fmt, ...) LogMaybe(Log::Level::Debug, true, fmt "\n", ##__VA_ARGS__)


/** Print a variable as "variableName = variableValue; ", without newline, as a Debug log.
 * Usage:
 * `LogVar(a); LogVar(b); LogLine(); // "a = ...; b = ...; "`
 *
 * `LogVar(object); LogLine(); // "object = ...; "`
*/
#define LogVar(variable) LogMaybe(Log::Level::Debug, true, "%s = %s; ", (#variable), CSTR(variable))

/** Print a new line, as a Debug log. */
#define LogLine() LogDebug("")


#endif // LOG_H
