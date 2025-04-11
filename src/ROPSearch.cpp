#include <assert.h>
#include <algorithm>

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"

#include "../deps/argparse/include/argparse/argparse.hpp"

#include "common/utils.hpp"
#include "InstructionConverter.hpp"
#include "RegisterQueryX86.hpp"
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

#pragma endregion Misc


#pragma region Configure argument parser
#if false
int ________Configure_argument_parser________;
#endif

ArgumentParser gProgramParser("ROPSearch", "1.0", default_arguments::help);
ArgumentParser gListCmdSubparser("list", "1.0", default_arguments::help);
ArgumentParser gAssemblyInfoCmdSubparser("asmInfo", "1.0", default_arguments::help);

#define SORT_CRIT_ADDRESS_ASC "address-asc"
#define SORT_CRIT_ADDRESS_DESC "address-desc"
#define SORT_CRIT_STRING_ASC "string-asc"
#define SORT_CRIT_STRING_DESC "string-desc"
#define SORT_CRIT_NUM_INSTRUCTIONS_ASC "num-instr-asc"
#define SORT_CRIT_NUM_INSTRUCTIONS_DESC "num-instr-desc"


void AddVerboseArgumentToParser(ArgumentParser& parser) {
    parser.add_argument("-v", "--verbose")
    .help("increases output verbosity")
    .action([&](const auto &) {
        int oldLogLevel = (int)Log::ProgramLogLevel;
        int newLogLevel = 2 * oldLogLevel;
        Log::ProgramLogLevel = (Log::Level)newLogLevel;
    })
    .append()
    .nargs(0);
}

void ConfigureListCommandSubparser() {
    gListCmdSubparser.add_description("List all instruction sequences found in the given source.");
    gListCmdSubparser.set_usage_max_line_width(160);

    AddVerboseArgumentToParser(gListCmdSubparser);

    // "Source" arguments
    gListCmdSubparser.add_usage_newline();
    auto &mutExGroup = gListCmdSubparser.add_mutually_exclusive_group(true);
    mutExGroup.add_argument("-pid", "--process-id")
        .help("the pid for the target running process. "
              "The tool needs permission to access the \"/proc/PID/maps\" file. "
              "For example, run it under the same user as the target process or under the super-user)")
        .metavar("PID")
        .scan<'i', int>();
    mutExGroup.add_argument("-exec", "--executable-path")
        .help("a path to an executable (ELF) file. "
              "The tool will load all executable segments found in the file (usually just one). "
              "Can be passed multiple times. "
              "Can be used with the \"--base-address\" argument")
        .metavar("PATH")
        .nargs(argparse::nargs_pattern::at_least_one);
    gListCmdSubparser.add_argument("-addr", "--base-address")
        .help("this argument is only relevant when used with \"--executable-path\". "
              "It's a hexadecimal address which will be used as a base address for a loaded executable segment. "
              "Can be passed multiple times and each new address will be used for the next found segment. "
              "If not enough addresses, then the `Elf64_Phdr.p_vaddr` value is used instead")
        .metavar("HEX")
        .scan<'x', unsigned long long>()
        .nargs(argparse::nargs_pattern::any)
        .default_value(vector<unsigned long long>{});

    // "Filter" arguments
    gListCmdSubparser.add_usage_newline();
    gListCmdSubparser.add_argument("-mini", "--min-instructions")
        .help("the minimum number of assembly instructions contained in the same instruction sequence")
        .metavar("INT")
        .default_value(1)
        .scan<'i', int>()
        .nargs(1);
    gListCmdSubparser.add_argument("-maxi", "--max-instructions")
        .help("the maximum number of assembly instructions contained in the same instruction sequence")
        .metavar("INT")
        .default_value(10)
        .scan<'i', int>()
        .nargs(1);
    gListCmdSubparser.add_argument("--no-null")
        .help("ignore instruction sequences that have a \"0x00\" byte in their virtual memory address. Note: This may print nothing on 64bit arch.")
        .flag();
    gListCmdSubparser.add_argument("--query")
        .help("a register query for filtering the instruction sequences. E.g. \"read(rax) & write(bx)\".")
        .metavar("STR")
        .nargs(1);
    gListCmdSubparser.add_argument("--pack", "--pack-partial-registers")
        .help("Treat partial registers as being the same register when used in the '--query' argument.")
        .flag();

    // "Output" arguments
    gListCmdSubparser.add_usage_newline();
    gListCmdSubparser.add_argument("-asm", "--assembly-syntax")
        .help("desired assembly syntax for the output instructions. Possible values: \"intel\", \"att\"")
        .metavar("STR")
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
        .metavar("STR")
        .nargs(1, 3)
        .choices(SORT_CRIT_ADDRESS_ASC, SORT_CRIT_ADDRESS_DESC,
                 SORT_CRIT_STRING_ASC, SORT_CRIT_STRING_DESC,
                 SORT_CRIT_NUM_INSTRUCTIONS_ASC, SORT_CRIT_NUM_INSTRUCTIONS_DESC);

    gProgramParser.add_subparser(gListCmdSubparser);
}

void ConfigureAssemblyInfoCommandSubparser() {
    gAssemblyInfoCmdSubparser.add_description("Print what information Capstone knows about some assembly instructions.");
    gAssemblyInfoCmdSubparser.set_usage_max_line_width(160);

    AddVerboseArgumentToParser(gAssemblyInfoCmdSubparser);

    gAssemblyInfoCmdSubparser.add_usage_newline();

    gAssemblyInfoCmdSubparser.add_argument("instructions")
        .help("the instruction(s) for which info will be printed. "
              "Multiple instructions can be separated by a ';' character.")
        .metavar("STR")
        .nargs(1);
    gAssemblyInfoCmdSubparser.add_argument("-asm", "--assembly-syntax")
        .help("assembly syntax of the input instructions. Possible values: \"intel\", \"att\"")
        .metavar("STR")
        .default_value("intel")
        .choices("intel", "att")
        .nargs(1);
    gAssemblyInfoCmdSubparser.add_argument("-addr", "--base-address")
        .help("the hexadecimal virtual memory address of the first instruction in the input. "
              "This is relevant only for some instructions like relative jumps.")
        .metavar("HEX")
        .default_value(0ULL)
        .scan<'x', unsigned long long>()
        .nargs(1);

    gProgramParser.add_subparser(gAssemblyInfoCmdSubparser);
}

void ConfigureArgumentParser() {
    gProgramParser.add_argument("--version")
    .help("prints version information and exits")
    .action([&](const auto &) {
        LogInfo("Version: %s", "1.0");
        exit(0);
    })
    .default_value(false)
    .implicit_value(true)
    .nargs(0);

    ConfigureListCommandSubparser();
    ConfigureAssemblyInfoCommandSubparser();
}

#pragma endregion Configure argument parser


#pragma region List command
#if false
int ________List_command________;
#endif

void SortListOutput(const vector< pair<unsigned long long, vector<string>> >& instrSeqs,
                    vector<unsigned>& validIndexes)
{
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
    auto comparator = [&](unsigned idxA, unsigned idxB){
        const elemType& a = instrSeqs[idxA];
        const elemType& b = instrSeqs[idxB];

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

    sort(validIndexes.begin(), validIndexes.end(), comparator);
}

vector<unsigned>
FilterInstructionSequencesByListCmdArgs(const vector< pair<unsigned long long, vector<string>> >& instrSeqs,
                                        const vector<vector<RegisterInfo>>& allRegInfoSeqs) {
    const int minInstructions = gListCmdSubparser.get<int>("--min-instructions");
    const bool ignoreNullBytes = gListCmdSubparser.get<bool>("--no-null");
    const bool haveRegisterQuery = gListCmdSubparser.is_used("--query");
    const bool packPartialRegistersInQuery = gListCmdSubparser.get<bool>("--pack");

    vector<unsigned> validIndexes;
    for (unsigned idx = 0; idx < instrSeqs.size(); ++idx) {
        validIndexes.push_back(idx);
    }

    // Apply the "--min-instructions" filter.
    validIndexes.erase(remove_if(validIndexes.begin(), validIndexes.end(), [&](unsigned idx) {
        const auto& p = instrSeqs[idx];
        const vector<string>& instructionSequence = p.second;

        return (int)instructionSequence.size() < minInstructions;
    }), validIndexes.end());

    // Apply the "--no-null" filter
    if (ignoreNullBytes) {
        validIndexes.erase(remove_if(validIndexes.begin(), validIndexes.end(), [&](unsigned idx) {
            const auto& p = instrSeqs[idx];
            const unsigned long long& addr = p.first;
            byteSequence addressBytes = BytesOfInteger(addr);

            return find(addressBytes.begin(), addressBytes.end(), (ROP::byte)0x00) != addressBytes.end();
        }), validIndexes.end());
    }

    // Apply the "--query" filter.
    if (haveRegisterQuery) {
        assert(instrSeqs.size() == allRegInfoSeqs.size());
        string queryString = gListCmdSubparser.get<string>("--query");
        RegisterQueryX86 rq(queryString);

        if (packPartialRegistersInQuery) {
            rq.enablePartialRegisterPacking();
        }

        LogVerbose("Query representation: %s", rq.getStringRepresentationOfQuery().c_str());
        LogVerbose(""); // New line.

        validIndexes.erase(remove_if(validIndexes.begin(), validIndexes.end(), [&](unsigned idx) {
            const vector<RegisterInfo>& regInfoList = allRegInfoSeqs[idx];
            return rq.matchesRegisterInfoOfInstructionSequence(regInfoList) == false;
        }), validIndexes.end());
    }

    return validIndexes;
}

void DoListCommand() {
    assertMessage(gListCmdSubparser, "Inner logic error...");

    const int minInstructions = gListCmdSubparser.get<int>("--min-instructions");
    const int maxInstructions = gListCmdSubparser.get<int>("--max-instructions");
    const string asmSyntaxString = gListCmdSubparser.get<string>("--assembly-syntax");
    const bool haveRegisterQuery = gListCmdSubparser.is_used("--query");
    const bool packPartialRegistersInQuery = gListCmdSubparser.get<bool>("--pack");

    assertMessage(1 <= minInstructions && minInstructions <= 100, "Please input a different number of min instructions...");
    assertMessage(1 <= maxInstructions && maxInstructions <= 100, "Please input a different number of max instructions...");
    assertMessage(minInstructions <= maxInstructions, "Please input a different number of min/max instructions...");

    // Apply "--max-instructions" filter. Specifically, instructions will be filtered in the object constructor.
    VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = maxInstructions;

    // Apply "--assembly-syntax" output option.
    ROP::AssemblySyntax desiredSyntax = (asmSyntaxString == "intel") ? ROP::AssemblySyntax::Intel : ROP::AssemblySyntax::ATT;
    VirtualMemoryInstructions::innerAssemblySyntax = desiredSyntax;

    if (haveRegisterQuery) {
        // Check if the query string is valid.
        string queryString = gListCmdSubparser.get<string>("--query");
        RegisterQueryX86 rq(queryString);
        assertMessage(rq.isValidQuery(), "Got invalid register query: %s", queryString.c_str());

        // If we have a "--query" argument, then we will have to compute the register info for each instruction.
        VirtualMemoryInstructions::computeRegisterInfo = true;
    }
    else {
        assertMessage(!packPartialRegistersInQuery,
                      "The '--pack' argument makes sense only when passed alongside the '--query' argument.");
    }

    VirtualMemoryInstructions vmInstructions = [&]() {
        if (auto pid = gListCmdSubparser.present<int>("--process-id")) {
            return VirtualMemoryInstructions(*pid);
        }
        else {
            vector<string> execs = gListCmdSubparser.get<vector<string>>("--executable-path");
            vector<unsigned long long> addrs = gListCmdSubparser.get<vector<unsigned long long>>("--base-address");
            return VirtualMemoryInstructions(execs, addrs);
        }
    }();

    // Get the instruction sequences found in the target.
    vector< pair<unsigned long long, vector<string>> > instrSeqs;
    vector<vector<RegisterInfo>> allRegInfoSeqs;
    if (haveRegisterQuery) {
        instrSeqs = vmInstructions.getInstructionSequences(&allRegInfoSeqs);
    }
    else {
        instrSeqs = vmInstructions.getInstructionSequences(NULL);
    }

    // Filter the elements according to command-line arguments.
    vector<unsigned> validIndexes = FilterInstructionSequencesByListCmdArgs(instrSeqs, allRegInfoSeqs);

    // Sort the output according to the "--sort" argument.
    SortListOutput(instrSeqs, validIndexes);

    // Print each instruction sequence.
    InstructionConverter ic;
    for (unsigned idx : validIndexes) {
        const auto& p = instrSeqs[idx];
        const unsigned long long& addr = p.first;
        const vector<string>& instructionSequence = p.second;

        string fullSequence = ic.concatenateInstructionsAsm(instructionSequence);
        LogInfo("0x%016llx: %s", addr, fullSequence.c_str());
    }

    LogInfo("");
    LogInfo("Found %u instruction sequences.", (unsigned)validIndexes.size());
}

#pragma endregion List command


#pragma region Assembly Info command
#if false
int ________Assembly_Info_command________;
#endif

void DoAssemblyInfoCommand() {
    assertMessage(gAssemblyInfoCmdSubparser, "Inner logic error...");

    const string asmInstructionsString = gAssemblyInfoCmdSubparser.get<string>("instructions");
    const string asmSyntaxString = gAssemblyInfoCmdSubparser.get<string>("--assembly-syntax");
    const unsigned long long address = gAssemblyInfoCmdSubparser.get<unsigned long long>("--base-address");

    ROP::AssemblySyntax inputAsmSyntax = (asmSyntaxString == "intel") ? ROP::AssemblySyntax::Intel : ROP::AssemblySyntax::ATT;

    InstructionConverter ic;
    ic.printCapstoneInformationForInstructions(asmInstructionsString, inputAsmSyntax, address);
}

#pragma endregion Assembly Info command


#pragma region Main
#if false
int ________Main________;
#endif

int main(int argc, char* argv[]) {
    // Set default log level.
    Log::ProgramLogLevel = Log::Level::Info;

    ConfigureArgumentParser();

    try {
        gProgramParser.parse_args(argc, argv);
    }
    catch (const exception& err) {
        exitError("Argument parser error: %s", err.what());
    }

    PrintProcessInformation();

    if (gListCmdSubparser) {
        DoListCommand();
        return 0;
    }

    if (gAssemblyInfoCmdSubparser) {
        DoAssemblyInfoCommand();
        return 0;
    }

    LogInfo("No command-line arguments. Try \"--help\"!");
    return 0;
}

#pragma endregion Main
