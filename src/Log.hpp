#ifndef LOG_H
#define LOG_H


class Log {
    public:

    enum class Level {
        Debug,
        Verbose,
        Info,
        Warn,
        Error
    };

    static Level ProgramLogLevel;
};


#define LogBase(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define LogMaybe(level, fmt, ...) \
    do { \
        if (level >= Log::ProgramLogLevel) { \
            LogBase(fmt, ##__VA_ARGS__); \
        } \
    } while (0)

#define LogDebug(fmt, ...) LogMaybe(Log::Level::Debug, fmt, ##__VA_ARGS__)
#define LogVerbose(fmt, ...) LogMaybe(Log::Level::Verbose, fmt, ##__VA_ARGS__)
#define LogInfo(fmt, ...) LogMaybe(Log::Level::Info, fmt, ##__VA_ARGS__)
#define LogWarn(fmt, ...) LogMaybe(Log::Level::Warn, fmt, ##__VA_ARGS__)
#define LogError(fmt, ...) LogMaybe(Log::Level::Error, fmt, ##__VA_ARGS__)


#endif // LOG_H
