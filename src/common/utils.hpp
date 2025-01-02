#ifndef UTILS_H
#define UTILS_H

#include <filesystem>
#include <iostream>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PUGIXML_HEADER_ONLY
#include "../../deps/pugixml/src/pugixml.hpp"

#include "types.hpp"
#include "../Log.hpp"


#define pv(x) std::cout<<#x<<" = "<<(x)<<"; ";std::cout.flush()
#define pn std::cout<<std::endl

#define exitError(format, ...) \
    do { \
        LogError(""); \
        LogError(format, ##__VA_ARGS__); \
        LogError("exit(-1);"); \
        LogError(""); \
        exit(-1); \
    } while(0)

#define assertMessage(condition, format, ...) \
    do { \
        if (!(condition)) { \
            LogError(""); \
            LogError("Assert failed!"); \
            LogError("Assert location:  %s:%i (%s)", __FILE__, __LINE__, __func__); \
            LogError("Assert condition: " #condition); \
            LogError("Assert message:   " format, ##__VA_ARGS__); \
            LogError(""); \
            exit(-1); \
        } \
    } while(0)

#define UNUSED(variable) do { (void)(variable); } while (0)


// To avoid warnings if any of the following functions aren't used in every file that includes the header.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static inline std::string GetAbsPathToProcExecutable() {
    char buffer[PATH_MAX];
    memset(buffer, 0, sizeof(buffer));

    int ret = readlink("/proc/self/exe", buffer, sizeof(buffer)-1);
    if (ret == -1) {
        exitError("readlink(\"/proc/self/exe\") failed");
    }

    return std::string(buffer);
}

static inline void SetCWDToExecutableLocation() {
    std::filesystem::path execPath(GetAbsPathToProcExecutable());

    // Remove the file path component at the end of the path.
    std::filesystem::path parentDirPath = execPath.remove_filename();

    // Set Current Working Directory
    std::filesystem::current_path(parentDirPath);
}

static std::string XmlNodeToString(pugi::xml_node node) {

    // Declare helper class;
    struct xml_string_writer : pugi::xml_writer {
        std::string result;

        virtual void write(const void *data, size_t size)
        {
            result.append((const char *)data, size);
        }
    };

    xml_string_writer writer;
    node.print(writer);

    return writer.result;
}

template<typename integerType>
static ROP::byteSequence BytesOfInteger(integerType integer) {
    ROP::byteSequence bytes;

    for (unsigned k = 0; k < sizeof(integer); ++k, integer >>= 8) {
        ROP::byte b = (integer & 0xFF);
        bytes.push_back(b);
    }

    return bytes;
}


#pragma GCC diagnostic pop


#endif // UTILS_H
