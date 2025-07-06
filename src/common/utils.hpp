#ifndef UTILS_H
#define UTILS_H

#include <filesystem>
#include <iostream>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sstream>
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
    // Get the path to the running executable.
    std::filesystem::path execPath = GetAbsPathToProcExecutable();

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

    for (unsigned k = 0; k < sizeof(integerType); ++k, integer >>= 8) {
        ROP::byte b = (integer & 0xFF);
        bytes.push_back(b);
    }

    return bytes;
}

template<typename integerType>
static std::string GetBinaryReprOfInteger(integerType integer) {
    std::ostringstream ss;

    for (int k = sizeof(integer)*8 - 1; k >= 0; --k) {
        if (integer & (1<<k)) {
            ss << '1';
        }
        else {
            ss << '0';
        }
    }

    return ss.str();
}

template<typename integerType>
static unsigned GetMinimumNumberOfBytesToStoreInteger(integerType integer) {
    unsigned numBytes = 1;
    integer >>= 8;

    while (integer != 0) {
        numBytes += 1;
        integer >>= 8;
    }

    return numBytes;
}

static void RightPadString(std::string& str, unsigned minSize, char padChar) {
    if (str.size() < minSize) {
        str += std::string(minSize - str.size(), padChar);
    }
}

static void RightTrimString(std::string& str, const char *badChars = " \t\n\r\f\v") {
    const std::size_t pos = str.find_last_not_of(badChars);
    str.erase(pos + 1);
}

template<int numBytes>
static int32_t ConvertLittleEndianBytesTo4ByteInteger(const ROP::byte *ptr) {
    int32_t result = 0;

    for (int i = 0; i < numBytes; ++i) {
        result += (ptr[i] << (i*8));
    }

    return result;
}


#pragma GCC diagnostic pop


#endif // UTILS_H
