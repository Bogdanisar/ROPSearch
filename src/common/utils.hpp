#ifndef UTILS_H
#define UTILS_H

#include <filesystem>
#include <iostream>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../deps/pugixml/src/pugixml.hpp"


#define pv(x) std::cout<<#x<<" = "<<(x)<<"; ";std::cout.flush()
#define pn std::cout<<std::endl

#define exiterror(format, ...) fprintf(stderr, (format "\n" "exit(-1);\n"), ##__VA_ARGS__); fflush(stderr); exit(-1)
#define assertMessage(condition, format, ...) \
    do { \
        if (!(condition)) { exiterror("Assert failed!\n" "Assert condition: " #condition "\n" "Assert message:   " format, ##__VA_ARGS__); } \
    } while(0)

#define UNUSED(variable) do { (void)(variable); } while (0)


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

static inline std::string getAbsPathToProcExecutable() {
    char buffer[PATH_MAX];
    memset(buffer, 0, sizeof(buffer));

    int ret = readlink("/proc/self/exe", buffer, sizeof(buffer)-1);
    if (ret == -1) {
        exiterror("readlink(\"/proc/self/exe\") failed");
    }

    return std::string(buffer);
}

static inline void setCWDToExecutableLocation() {
    std::filesystem::path execPath(getAbsPathToProcExecutable());

    // Remove the file path component at the end of the path.
    std::filesystem::path parentDirPath = execPath.remove_filename();

    // Set Current Working Directory
    std::filesystem::current_path(parentDirPath);
}

static std::string xmlNodeToString(pugi::xml_node node) {

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

#pragma GCC diagnostic pop


#endif // UTILS_H
