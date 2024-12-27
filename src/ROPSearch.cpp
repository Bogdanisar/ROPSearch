#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"

#include "../deps/argparse/include/argparse/argparse.hpp"

#include "common/utils.hpp"
#include "ELFParser.hpp"
#include "GadgetCatalog.hpp"
#include "GadgetMould.hpp"
#include "InstructionConverter.hpp"
#include "VirtualMemoryInfo.hpp"
#include "VirtualMemoryMapping.hpp"


using namespace std;
using namespace argparse;
using namespace ROP;


#pragma region Misc
#if false
int ________Misc________;
#endif

void PrintProcessInformation() {
    LogVerbose("My PID: %i", (int)getpid());
}

void NormalizeCWD() {
    SetCWDToExecutableLocation();
    string currentWorkingDirectory = filesystem::current_path();
    LogVerbose("Set Current Working Directory to: \"%s\"\n", CSTR(currentWorkingDirectory));
}

#pragma endregion Misc


#pragma region Configure argument parser
#if false
int ________Configure_argument_parser________;
#endif

ArgumentParser gProgramParser("ROPSearch");

void ConfigureArgumentParser() {
    Log::ProgramLogLevel = Log::Level::Info;
    gProgramParser.add_argument("-v", "--verbose")
    .action([&](const auto &) {
        int oldLogLevel = (int)Log::ProgramLogLevel;
        int newLogLevel = 2 * oldLogLevel;
        Log::ProgramLogLevel = (Log::Level)newLogLevel;
    })
    .append()
    .nargs(0);
}

#pragma endregion Configure argument parser


#pragma region Main
#if false
int ________Main________;
#endif

int main(int argc, char* argv[]) {
    // UNUSED(argc); UNUSED(argv);

    ConfigureArgumentParser();

    try {
        gProgramParser.parse_args(argc, argv);
    }
    catch (const exception& err) {
        exitError("Argument parser error: %s", err.what());
    }

    PrintProcessInformation();
    NormalizeCWD();

    LogError("LogError message...");
    LogWarn("LogWarn message...");
    LogInfo("LogInfo message...");
    LogVerbose("LogVerbose message...");
    LogDebug("LogDebug message...");

    return 0;
}

#pragma endregion Main
