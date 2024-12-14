#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"

#include "common/utils.hpp"
#include "ELFParser.hpp"
#include "GadgetCatalog.hpp"
#include "GadgetMould.hpp"
#include "InstructionConverter.hpp"
#include "VirtualMemoryInfo.hpp"
#include "VirtualMemoryMapping.hpp"


using namespace std;
using namespace ROP;


void printProcessInformation(int argc, char* argv[]) {
    int myPID = getpid();
    pv(myPID); pn;

    long pageSize = sysconf(_SC_PAGESIZE);
    pv(pageSize); pn;

    string execPath = getAbsPathToProcExecutable();
    pv(execPath); pn;

    for (int i = 0; i < argc; ++i) {
        printf("arg[%i] = %s\n", i, argv[i]);
    }
}

void normalizeCWD() {
    string currentWorkingDirectory = std::filesystem::current_path();
    pv(currentWorkingDirectory); pn;

    printf("Setting CWD to the location of this binary...\n");
    setCWDToExecutableLocation();

    currentWorkingDirectory = std::filesystem::current_path();
    pv(currentWorkingDirectory); pn;
}


int main(int argc, char* argv[]) {
    // UNUSED(argc); UNUSED(argv);

    printProcessInformation(argc, argv); pn;
    normalizeCWD(); pn;

    return 0;
}
