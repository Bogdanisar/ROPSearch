#ifndef UTILS_H
#define UTILS_H

#include <filesystem>
#include <iostream>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define pv(x) std::cout<<#x<<" = "<<(x)<<"; ";std::cout.flush()
#define pn std::cout<<std::endl

#define exiterror(msg) std::cerr << (msg) << '\n' << "exit(-1);" << std::endl; exit(-1)
#define assertMessage(condition, msg) \
    do { \
        if (!(condition)) { exiterror(msg); } \
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

#pragma GCC diagnostic pop


#endif // UTILS_H
