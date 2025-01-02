#include <assert.h>
#include <algorithm>

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"

#include "../deps/argparse/include/argparse/argparse.hpp"

#include "common/utils.hpp"
#include "InstructionConverter.hpp"
#include "VirtualMemoryInstructions.hpp"


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

ArgumentParser gProgramParser("ROPSearch", "1.0", default_arguments::help);
ArgumentParser gListCmdSubparser("list", "1.0", default_arguments::help);

#define SORT_CRIT_ADDRESS_ASC "address-asc"
#define SORT_CRIT_ADDRESS_DESC "address-desc"
#define SORT_CRIT_STRING_ASC "string-asc"
#define SORT_CRIT_STRING_DESC "string-desc"
#define SORT_CRIT_NUM_INSTRUCTIONS_ASC "num-instr-asc"
#define SORT_CRIT_NUM_INSTRUCTIONS_DESC "num-instr-desc"


void ConfigureListCommandSubparser() {
    gListCmdSubparser.add_description("List all instruction sequences found in the given source.");

    gListCmdSubparser.add_group("Source");
    gListCmdSubparser.add_argument("-pid", "--process-id")
        .help("the pid for the target running process. "
              "The tool needs permission to access the \"/proc/PID/maps\" file. "
              "For example, run it under the same user as the target process or under the super-user)")
        .metavar("PID")
        .required()
        .scan<'i', int>();

    gListCmdSubparser.add_group("Filters");
    gListCmdSubparser.add_argument("-mini", "--min-instructions")
        .help("the minimum number of assembly instructions contained in the same instruction sequence")
        .metavar("MIN_INS")
        .default_value(1)
        .scan<'i', int>()
        .nargs(1);
    gListCmdSubparser.add_argument("-maxi", "--max-instructions")
        .help("the maximum number of assembly instructions contained in the same instruction sequence")
        .metavar("MAX_INS")
        .default_value(10)
        .scan<'i', int>()
        .nargs(1);
    gListCmdSubparser.add_argument("--no-null")
        .help("ignore instruction sequences that have a \"0x00\" byte in their virtual memory address. Note: This may print nothing on 64bit arch.")
        .flag();

    gListCmdSubparser.add_group("Output");
    gListCmdSubparser.add_argument("-asm", "--assembly-syntax")
        .help("desired assembly syntax for the output instructions. Possible values: \"intel\", \"att\"")
        .metavar("ASM")
        .default_value("intel")
        .choices("intel", "att")
        .nargs(1);
    gListCmdSubparser.add_argument("-s", "--sort")
        .help("options for sorting the output instructions. "
              "Can be passed multiple times for a list of criteria. Most important first. "
              "Possible values: '" SORT_CRIT_ADDRESS_ASC "', '" SORT_CRIT_ADDRESS_DESC "', "
                               "'" SORT_CRIT_STRING_ASC "', '" SORT_CRIT_STRING_DESC "', "
                               "'" SORT_CRIT_NUM_INSTRUCTIONS_ASC "', '" SORT_CRIT_NUM_INSTRUCTIONS_DESC "'. "
              "Default value: '" SORT_CRIT_ADDRESS_ASC "', '" SORT_CRIT_NUM_INSTRUCTIONS_ASC "'")
        .metavar("CRITERION")
        .nargs(1, 3)
        .choices(SORT_CRIT_ADDRESS_ASC, SORT_CRIT_ADDRESS_DESC,
                 SORT_CRIT_STRING_ASC, SORT_CRIT_STRING_DESC,
                 SORT_CRIT_NUM_INSTRUCTIONS_ASC, SORT_CRIT_NUM_INSTRUCTIONS_DESC);

    gProgramParser.add_subparser(gListCmdSubparser);
}

void ConfigureArgumentParser() {
    gProgramParser.add_argument("--version")
    .help("prints version information and exits")
    .action([&](const auto &) {
        LogInfo("Version: %s", "1.0");
        std::exit(0);
    })
    .default_value(false)
    .implicit_value(true)
    .nargs(0);

    Log::ProgramLogLevel = Log::Level::Info;
    gProgramParser.add_argument("-v", "--verbose")
    .help("increases output verbosity")
    .action([&](const auto &) {
        int oldLogLevel = (int)Log::ProgramLogLevel;
        int newLogLevel = 2 * oldLogLevel;
        Log::ProgramLogLevel = (Log::Level)newLogLevel;
    })
    .append()
    .nargs(0);

    ConfigureListCommandSubparser();
}

#pragma endregion Configure argument parser


#pragma region List command
#if false
int ________List_command________;
#endif

void SortListOutput(vector< pair<unsigned long long, vector<string>> >& instrSeqs) {
    vector<string> sortCriteria = gListCmdSubparser.get<vector<string>>("--sort");
    if (sortCriteria.size() == 0) {
        // Set default value.
        sortCriteria = {SORT_CRIT_ADDRESS_ASC, SORT_CRIT_NUM_INSTRUCTIONS_ASC};
    }

    for (int i = 0; i < (int)sortCriteria.size(); ++i) {
        for (int j = i + 1; j < (int)sortCriteria.size(); ++j) {
            assertMessage(sortCriteria[i] != sortCriteria[j],
                          "You can't list the same sort criterion multiple times (\"%s\").", sortCriteria[i].c_str());
        }
    }

    for (int i = 0; i < (int)sortCriteria.size(); ++i) {
        for (int j = i + 1; j < (int)sortCriteria.size(); ++j) {
            string criterion1MainPart = sortCriteria[i].substr(0, sortCriteria[i].find_last_of("-"));
            string criterion2MainPart = sortCriteria[j].substr(0, sortCriteria[j].find_last_of("-"));
            assertMessage(criterion1MainPart != criterion2MainPart,
                          "You can't have both the ascending and descending variants of the same sort criterion (\"%s\")",
                          criterion1MainPart.c_str());
        }
    }

    using elemType = pair<unsigned long long, vector<string>>;
    auto comparator = [&](const elemType& a, const elemType& b){
        for (int i = 0; i < (int)sortCriteria.size(); ++i) {
            string criterion = sortCriteria[i];
            if (criterion == SORT_CRIT_ADDRESS_ASC) {
                auto addressA = a.first, addressB = b.first;
                if (addressA < addressB) {
                    return true;
                }
                if (addressA > addressB) {
                    return false;
                }
            }
            else if (criterion == SORT_CRIT_ADDRESS_DESC) {
                auto addressA = a.first, addressB = b.first;
                if (addressA > addressB) {
                    return true;
                }
                if (addressA < addressB) {
                    return false;
                }
            }
            else if (criterion == SORT_CRIT_STRING_ASC) {
                if (a.second < b.second) {
                    return true;
                }
                if (a.second > b.second) {
                    return false;
                }
            }
            else if (criterion == SORT_CRIT_STRING_DESC) {
                if (a.second > b.second) {
                    return true;
                }
                if (a.second < b.second) {
                    return false;
                }
            }
            else if (criterion == SORT_CRIT_NUM_INSTRUCTIONS_ASC) {
                auto sizeA = a.second.size(), sizeB = b.second.size();
                if (sizeA < sizeB) {
                    return true;
                }
                if (sizeA > sizeB) {
                    return false;
                }
            }
            else if (criterion == SORT_CRIT_NUM_INSTRUCTIONS_DESC) {
                auto sizeA = a.second.size(), sizeB = b.second.size();
                if (sizeA > sizeB) {
                    return true;
                }
                if (sizeA < sizeB) {
                    return false;
                }
            }
            else {
                exitError("Sort criterion doesn't match possible values: %s", criterion.c_str());
            }
        }

        return false;
    };

    sort(instrSeqs.begin(), instrSeqs.end(), comparator);
}

void DoListCommand() {
    assertMessage(gListCmdSubparser, "Inner logic error...");

    const int targetPid = gListCmdSubparser.get<int>("-pid");
    const int minInstructions = gListCmdSubparser.get<int>("--min-instructions");
    const int maxInstructions = gListCmdSubparser.get<int>("--max-instructions");
    const string asmSyntaxString = gListCmdSubparser.get<string>("--assembly-syntax");
    const bool ignoreNullBytes = gListCmdSubparser.get<bool>("--no-null");

    assertMessage(1 <= minInstructions && minInstructions <= 100, "Please input a different number of min instructions...");
    assertMessage(1 <= maxInstructions && maxInstructions <= 100, "Please input a different number of max instructions...");
    assertMessage(minInstructions <= maxInstructions, "Please input a different number of min/max instructions...");

    // Apply "--max-instructions" filter. Specifically, instructions will be filtered in the object constructor.
    VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = maxInstructions;

    // Apply "--assembly-syntax" output option.
    ROP::AssemblySyntax desiredSyntax = (asmSyntaxString == "intel") ? ROP::AssemblySyntax::Intel : ROP::AssemblySyntax::ATT;
    VirtualMemoryInstructions::innerAssemblySyntax = desiredSyntax;

    InstructionConverter ic;
    VirtualMemoryInstructions vmInstructions(targetPid);
    auto instrSeqs = vmInstructions.getInstructionSequences();

    // Sort the output according to the "--sort" argument.
    SortListOutput(instrSeqs);

    LogInfo("Found instruction sequences:");
    for (const auto& p : instrSeqs) {
        unsigned long long addr = p.first;
        vector<string> instructionSequence = p.second;

        // Apply the "--min-instructions" filter.
        if ((int)instructionSequence.size() < minInstructions) {
            continue;
        }

        // Apply the "--no-null" filter
        if (ignoreNullBytes) {
            byteSequence addressBytes = BytesOfInteger(addr);
            if (find(addressBytes.begin(), addressBytes.end(), (ROP::byte)0x00) != addressBytes.end()) {
                continue;
            }
        }

        string fullSequence = ic.concatenateInstructionsAsm(instructionSequence);
        LogInfo("0x%10llx: %s", addr, fullSequence.c_str());
    }
}

#pragma endregion List command


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

    if (gListCmdSubparser) {
        DoListCommand();
        return 0;
    }

    LogInfo("No command-line arguments. Try \"--help\"!");
    return 0;
}

#pragma endregion Main
