#include <assert.h>
#include <algorithm>

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"

#include "../deps/argparse/include/argparse/argparse.hpp"

#include "common/utils.hpp"
#include "InstructionConverter.hpp"
#include "PayloadGenX86.hpp"
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
ArgumentParser gFindDataCmdSubparser("findData", "1.0", default_arguments::help);
ArgumentParser gROPChainCmdSubparser("ropChain", "1.0", default_arguments::help);

#define SORT_CRIT_ADDRESS_ASC "address-asc"
#define SORT_CRIT_ADDRESS_DESC "address-desc"
#define SORT_CRIT_STRING_ASC "string-asc"
#define SORT_CRIT_STRING_DESC "string-desc"
#define SORT_CRIT_NUM_INSTRUCTIONS_ASC "num-instr-asc"
#define SORT_CRIT_NUM_INSTRUCTIONS_DESC "num-instr-desc"

#define ROPCHAIN_TYPE_SHELLNULLNULL "shellNullNull"


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
              "For example, run it under the same user as the target process or under the super-user")
        .metavar("PID")
        .scan<'i', int>();
    mutExGroup.add_argument("-exec", "--executable-path")
        .help("a path to an executable (ELF) file. "
              "The tool will load all executable segments found in the file (usually just one). "
              "Can pass multiple paths. "
              "Can be used with the \"--base-address\" argument")
        .metavar("PATH")
        .nargs(argparse::nargs_pattern::at_least_one);
    gListCmdSubparser.add_argument("-addr", "--base-address")
        .help("this argument is only relevant when used with \"--executable-path\". "
              "It's a hexadecimal address which will be used as a base address "
              "at which the segments of an ELF file are loaded. "
              "Can pass multiple values and each new base address will be used for the next ELF file. "
              "If not enough addresses, then 0 will be used as a default.")
        .metavar("HEX")
        .scan<'x', addressType>()
        .nargs(argparse::nargs_pattern::any)
        .default_value(vector<addressType>{});

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
    gListCmdSubparser.add_argument("--bad-bytes")
        .help("ignore instruction sequences that have any of the specified bytes in their virtual memory address. "
              "Example: --bad-bytes 0x12 213 0o11. "
              "This will ignore any result whose address contains any of these bytes: 0x12 (hex), 213 (decimal) or 0o11 (octal).")
        .metavar("BYTE")
        .nargs(argparse::nargs_pattern::at_least_one);
    gListCmdSubparser.add_argument("--no-reljumps")
        .help("Ignore instruction sequences with direct relative 'jmp' instructions in the middle. "
              "They are usually included. "
              "Example: 'mov ebx, 0xffffffff; jmp 0xee73845b --> mov eax, ebx; pop ebx; ret'")
        .flag();
    gListCmdSubparser.add_argument("--include-reljump-starts")
        .help("Keep instruction sequences with direct relative 'jmp' instructions at the start. "
              "They are usually ignored. "
              "Example: 'jmp 0xee73845b --> mov eax, ebx; pop ebx; ret'")
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
    gListCmdSubparser.add_argument("--show-address-base")
        .help("Print the address of each instruction sequence as \"base + offset\".")
        .flag();
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
    gAssemblyInfoCmdSubparser.add_argument("-asize", "--arch-bit-size")
        .help("The bit size of the instruction architecture. Possible values: 32, 64")
        .metavar("INT")
        .default_value(64)
        .choices(32, 64)
        .scan<'i', int>()
        .nargs(1);
    gAssemblyInfoCmdSubparser.add_argument("-addr", "--base-address")
        .help("the hexadecimal virtual memory address of the first instruction in the input. "
              "This is relevant only for some instructions like relative jumps.")
        .metavar("HEX")
        .default_value(0ULL)
        .scan<'x', addressType>()
        .nargs(1);

    gProgramParser.add_subparser(gAssemblyInfoCmdSubparser);
}

void ConfigureFindDataSubparser() {
    gFindDataCmdSubparser.add_description("Find either strings or bytes in the given source.");
    gFindDataCmdSubparser.set_usage_max_line_width(160);

    AddVerboseArgumentToParser(gFindDataCmdSubparser);

    // "Source" arguments
    gFindDataCmdSubparser.add_usage_newline();
    auto &mutExGroup = gFindDataCmdSubparser.add_mutually_exclusive_group(true);
    mutExGroup.add_argument("-pid", "--process-id")
        .help("the pid for the target running process. "
              "The tool needs permission to access the \"/proc/PID/maps\" file. "
              "For example, run it under the same user as the target process or under the super-user")
        .metavar("PID")
        .scan<'i', int>();
    mutExGroup.add_argument("-exec", "--executable-path")
        .help("a path to an executable (ELF) file. "
              "The tool will load all loadable segments found in the file. "
              "Can pass multiple paths. "
              "Can be used with the \"--base-address\" argument")
        .metavar("PATH")
        .nargs(argparse::nargs_pattern::at_least_one);
    gFindDataCmdSubparser.add_argument("-addr", "--base-address")
        .help("this argument is only relevant when used with \"--executable-path\". "
              "It's a hexadecimal address which will be used as a base address "
              "at which the segments of an ELF file are loaded. "
              "Can pass multiple values and each new base address will be used for the next ELF file. "
              "If not enough addresses, then 0 will be used as a default.")
        .metavar("HEX")
        .scan<'x', addressType>()
        .nargs(argparse::nargs_pattern::any)
        .default_value(vector<addressType>{});

    // "Target Data" arguments
    gFindDataCmdSubparser.add_usage_newline();
    gFindDataCmdSubparser.add_argument("-b", "--bytes")
        .help("the byte sequence to find. Can pass multiple sequences. "
              "Example: -b 0x2F62696E2F7368 0x657869742030.")
        .metavar("BYTES")
        .nargs(argparse::nargs_pattern::at_least_one);
    gFindDataCmdSubparser.add_argument("-s", "--string")
        .help("the string to find. Can pass multiple strings. "
              "Example: -s '/bin/sh' 'exit 0'.")
        .metavar("STR")
        .nargs(argparse::nargs_pattern::at_least_one);

    gProgramParser.add_subparser(gFindDataCmdSubparser);
}

void ConfigureROPChainCommandSubparser() {
    gROPChainCmdSubparser.add_description("Automatically build a payload for a chain of Return-Oriented-Programming gadgets.");
    gROPChainCmdSubparser.set_usage_max_line_width(160);

    AddVerboseArgumentToParser(gROPChainCmdSubparser);

    // "Source" arguments
    gROPChainCmdSubparser.add_usage_newline();
    auto &mutExGroup = gROPChainCmdSubparser.add_mutually_exclusive_group(true);
    mutExGroup.add_argument("-pid", "--process-id")
        .help("the pid for the target running process. "
              "The tool needs permission to access the \"/proc/PID/maps\" file. "
              "For example, run it under the same user as the target process or under the super-user")
        .metavar("PID")
        .scan<'i', int>();
    mutExGroup.add_argument("-exec", "--executable-path")
        .help("a path to an executable (ELF) file. "
              "The tool will load all readable segments found in the file. "
              "Can pass multiple paths. "
              "Can be used with the \"--base-address\" argument")
        .metavar("PATH")
        .nargs(argparse::nargs_pattern::at_least_one);
    gROPChainCmdSubparser.add_argument("-addr", "--base-address")
        .help("this argument is only relevant when used with \"--executable-path\". "
              "It's a hexadecimal address which will be used as a base address "
              "at which the segments of an ELF file are loaded. "
              "Can pass multiple values and each new base address will be used for the next ELF file. "
              "If not enough addresses, then 0 will be used as a default.")
        .metavar("HEX")
        .scan<'x', addressType>()
        .nargs(argparse::nargs_pattern::any)
        .default_value(vector<addressType>{});

    // "Configuration" arguments
    gROPChainCmdSubparser.add_usage_newline();
    gROPChainCmdSubparser.add_argument("-t", "--type")
        .help("the kind of ROP-chain you want to generate. Options: \"" ROPCHAIN_TYPE_SHELLNULLNULL "\"")
        .metavar("STR")
        .nargs(1)
        .required()
        .choices(ROPCHAIN_TYPE_SHELLNULLNULL);
    gROPChainCmdSubparser.add_argument("--buffer-length")
        .help("approximate total byte size of the stack variables/buffers that need to be overflowed")
        .metavar("UINT")
        .nargs(1)
        .scan<'u', unsigned>()
        .required();
    gROPChainCmdSubparser.add_argument("-maxi", "--max-instructions")
        .help("the maximum number of assembly instructions contained in the same instruction sequence")
        .metavar("UINT")
        .nargs(1)
        .scan<'u', unsigned>()
        .default_value(10u);
    gROPChainCmdSubparser.add_argument("-mv", "--max-variants")
        .help("maximum number of instruction sequence variants to show for each step in the payload script. Pass 0 for \"all of them\"")
        .metavar("UINT")
        .nargs(1)
        .scan<'u', unsigned>()
        .default_value(5u);
    gROPChainCmdSubparser.add_argument("-mp", "--max-padding")
        .help("maximum number of padding bytes that is allowed for each instruction in each of the detected sequences")
        .metavar("UINT")
        .nargs(1)
        .scan<'u', unsigned>()
        .default_value(30u);
    gROPChainCmdSubparser.add_argument("--no-null")
        .help("ignore payload results that contain NULL (\"0x00\") bytes. Note: This may print nothing on 64bit arch")
        .flag();
    gROPChainCmdSubparser.add_argument("--allow-duplicates")
        .help("keep duplicate instruction sequence results when showing multiple variants in the payload script")
        .flag();

    // "Output" arguments
    gROPChainCmdSubparser.add_usage_newline();
    gROPChainCmdSubparser.add_argument("-pf", "--payload-file")
        .help("a path where you want the payload bytes to be written, as a binary file")
        .metavar("PATH")
        .nargs(1);
    gROPChainCmdSubparser.add_argument("-sf", "--script-file")
        .help("a path where you want the generated Python script (which can generate the payload bytes) to be written")
        .metavar("PATH")
        .nargs(1);

    gProgramParser.add_subparser(gROPChainCmdSubparser);
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
    ConfigureFindDataSubparser();
    ConfigureROPChainCommandSubparser();
}

#pragma endregion Configure argument parser


#pragma region List command
#if false
int ________List_command________;
#endif

void SortListOutput(const vector< pair<addressType, vector<string>> >& instrSeqs,
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

    using elemType = pair<addressType, vector<string>>;
    auto comparator = [&](unsigned idxA, unsigned idxB) {
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

bitset<256> GetBadBytesArguments() {
    vector<string> badBytesUnparsed = gListCmdSubparser.get<vector<string>>("--bad-bytes");
    bitset<256> badBytes;

    for (const string& byteString : badBytesUnparsed) {
        unsigned long long currentInteger;

        if (byteString.size() > 2 && byteString.compare(0, 2, "0x") == 0) {
            // Look for hexadecimal byte.
            int numCharsParsed;
            sscanf(byteString.c_str(), "0x%llx%n", &currentInteger, &numCharsParsed);

            // Check if we parsed the entire string as a hexadecimal integer.
            assertMessage(numCharsParsed == (int)byteString.size(),
                          "Invalid hex format for input byte: %s", byteString.c_str());
        }
        else if (byteString.find_first_not_of("0123456789") == string::npos) {
            // Look for decimal byte.
            int numCharsParsed;
            sscanf(byteString.c_str(), "%llu%n", &currentInteger, &numCharsParsed);

            // Check if we parsed the entire string as a decimal integer.
            assertMessage(numCharsParsed == (int)byteString.size(),
                          "Invalid decimal format for input byte: %s", byteString.c_str());
        }
        else if (byteString.size() > 2 && byteString.compare(0, 2, "0o") == 0) {
            // Look for octal byte.
            int numCharsParsed;
            sscanf(byteString.c_str(), "0o%llo%n", &currentInteger, &numCharsParsed);

            // Check if we parsed the entire string as an octal integer.
            assertMessage(numCharsParsed == (int)byteString.size(),
                          "Invalid octal format for input byte: %s", byteString.c_str());
        }
        else {
            exitError("Got wrong format for input byte: %s", byteString.c_str());
        }

        // Check if the value is a byte.
        assertMessage(currentInteger < 256,
                      "Integer value %s is too big for a byte!", byteString.c_str());

        badBytes.set(currentInteger, true);
    }

    const bool ignoreNullBytes = gListCmdSubparser.get<bool>("--no-null");
    if (ignoreNullBytes) {
        badBytes.set(0x00, true);
    }

    return badBytes;
}

vector<unsigned>
FilterInstructionSequencesByListCmdArgs(const VirtualMemoryInstructions& vmInstructions,
                                        const vector< pair<addressType, vector<string>> >& instrSeqs,
                                        vector<vector<RegisterInfo>>& allRegInfoSeqs) {
    const int minInstructions = gListCmdSubparser.get<int>("--min-instructions");
    const bool hasRegisterQueryArg = gListCmdSubparser.is_used("--query");
    const bool packPartialRegistersInQuery = gListCmdSubparser.get<bool>("--pack");
    BitSizeClass bsc = vmInstructions.getVirtualMemoryBytes().getProcessArchSize();

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

    // Apply the "--bad-bytes", "--no-null" filters.
    bitset<256> badBytes = GetBadBytesArguments();
    if (badBytes.size() > 0) {
        validIndexes.erase(remove_if(validIndexes.begin(), validIndexes.end(), [&](unsigned idx) {
            const auto& p = instrSeqs[idx];
            const addressType& addr = p.first;

            byteSequence addressBytes;
            if (bsc == BitSizeClass::BIT64) {
                addressBytes = BytesOfInteger((uint64_t)addr);
            }
            else {
                addressBytes = BytesOfInteger((uint32_t)addr);
            }

            for (const ROP::byte& currentAddressByte : addressBytes) {
                if (badBytes.test(currentAddressByte) == true) {
                    // Remove this instruction sequence from the list of results;
                    return true;
                }
            }

            // Keep this instruction sequence in the list of results;
            return false;
        }), validIndexes.end());
    }

    // Apply the "--query" filter.
    if (hasRegisterQueryArg) {
        assert(instrSeqs.size() == allRegInfoSeqs.size());
        string queryString = gListCmdSubparser.get<string>("--query");
        RegisterQueryX86 rq(queryString);

        if (packPartialRegistersInQuery) {
            rq.transformInstrSeqsToEnablePartialRegisterPacking(allRegInfoSeqs);
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
    const bool hasBadBytesArg = gListCmdSubparser.is_used("--bad-bytes");
    const bool ignoreRelativeJumps = gListCmdSubparser.is_used("--no-reljumps");
    const bool includeRelativeJumpStarts = gListCmdSubparser.is_used("--include-reljump-starts");
    const bool hasRegisterQueryArg = gListCmdSubparser.is_used("--query");
    const bool packPartialRegistersInQuery = gListCmdSubparser.get<bool>("--pack");
    const bool showAddressBase = gListCmdSubparser.get<bool>("--show-address-base");
    const string asmSyntaxString = gListCmdSubparser.get<string>("--assembly-syntax");

    assertMessage(1 <= minInstructions && minInstructions <= 100, "Please input a different number of min instructions...");
    assertMessage(1 <= maxInstructions && maxInstructions <= 100, "Please input a different number of max instructions...");
    assertMessage(minInstructions <= maxInstructions,
                  "Please input a different number for min instructions (%i) or for max instructions (%i)...",
                  minInstructions, maxInstructions);

    // Apply "--max-instructions" filter. Specifically, instructions will be filtered in the object constructor.
    VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = maxInstructions;

    // Apply "--no-reljumps" filter and "--include-reljump-starts" filters.
    // Specifically, instructions will be filtered in the object constructor.
    assertMessage(!(ignoreRelativeJumps && includeRelativeJumpStarts),
                  "The '--include-reljump-starts' option doesn't make sense with '--no-reljumps'.");
    VirtualMemoryInstructions::SearchForSequencesWithDirectRelativeJumpsInTheMiddle = !ignoreRelativeJumps;
    VirtualMemoryInstructions::IgnoreOutputSequencesThatStartWithDirectRelativeJumps = !includeRelativeJumpStarts;

    // Apply "--assembly-syntax" output option.
    ROP::AssemblySyntax desiredSyntax = (asmSyntaxString == "intel") ? ROP::AssemblySyntax::Intel : ROP::AssemblySyntax::ATT;
    VirtualMemoryInstructions::innerAssemblySyntax = desiredSyntax;

    if (hasBadBytesArg) {
        // Check if the input byte strings are formatted correctly.
        GetBadBytesArguments();
    }

    if (hasRegisterQueryArg) {
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
            vector<addressType> addrs = gListCmdSubparser.get<vector<addressType>>("--base-address");
            return VirtualMemoryInstructions(execs, addrs);
        }
    }();

    // Get the instruction sequences found in the target.
    vector< pair<addressType, vector<string>> > instrSeqs;
    vector<vector<RegisterInfo>> allRegInfoSeqs;
    if (hasRegisterQueryArg) {
        instrSeqs = vmInstructions.getInstructionSequences(&allRegInfoSeqs);
    }
    else {
        instrSeqs = vmInstructions.getInstructionSequences(NULL);
    }

    // Filter the elements according to command-line arguments.
    vector<unsigned> validIndexes = FilterInstructionSequencesByListCmdArgs(vmInstructions, instrSeqs, allRegInfoSeqs);

    // Sort the output according to the "--sort" argument.
    SortListOutput(instrSeqs, validIndexes);

    const VirtualMemoryBytes vmBytes = vmInstructions.getVirtualMemoryBytes();
    const vector<VirtualMemorySegmentBytes> vmCodeSegments = vmBytes.getExecutableSegments();

    // Compute a helper value for each virtual memory segment, so that
    // we can print the output nicely if the "--show-address-base" option was passed.
    vector<unsigned> neededNumberOfBytesForSegment;
    for (const auto& segm : vmCodeSegments) {
        addressType maxOffset = segm.endVirtualAddress - segm.startVirtualAddress - 1;
        unsigned numBytesOffset = GetMinimumNumberOfBytesToStoreInteger(maxOffset);
        neededNumberOfBytesForSegment.push_back(numBytesOffset);
    }
    neededNumberOfBytesForSegment.push_back(sizeof(addressType)); // default value.

    // Print each instruction sequence.
    for (unsigned idx : validIndexes) {
        const auto& p = instrSeqs[idx];
        const addressType& addr = p.first;
        const vector<string>& instructionSequence = p.second;
        string fullSequence = InstructionConverter::concatenateInstructionsAsm(instructionSequence);

        if (showAddressBase) {
            // Get the extra address information.
            unsigned segmentIndex = vmCodeSegments.size(); // default value.
            addressType addressBase = 0x0;
            addressType addressOffset = addr;
            for (unsigned s = 0; s < vmCodeSegments.size(); ++s) {
                const auto& segm = vmCodeSegments[s];
                if (segm.startVirtualAddress <= addr && addr < segm.endVirtualAddress) {
                    segmentIndex = s;
                    addressBase = segm.startVirtualAddress;
                    addressOffset = addr - addressBase;
                    break;
                }
            }

            BitSizeClass bsc = vmBytes.getProcessArchSize();
            unsigned addressBaseByteSize = (bsc == BitSizeClass::BIT64) ? 8 : 4;

            LogInfo("0x%0*llx + 0x%0*llx: %s",
                    2 * addressBaseByteSize, (unsigned long long)addressBase,
                    2 * neededNumberOfBytesForSegment[segmentIndex], (unsigned long long)addressOffset,
                    fullSequence.c_str());
        }
        else {
            BitSizeClass bsc = vmBytes.getProcessArchSize();
            unsigned addressByteSize = (bsc == BitSizeClass::BIT64) ? 8 : 4;

            LogInfo("0x%0*llx: %s",
                    2 * addressByteSize, (unsigned long long)addr,
                    fullSequence.c_str());
        }
    }

    LogInfo(""); // new line
    LogInfo("Found %u instruction sequences.", (unsigned)validIndexes.size());

    if (showAddressBase) {
        // Print each segment address space at the end of the output, for convenience.

        LogInfo(""); // new line
        LogInfo("Virtual memory segments:");

        for (const auto& segm : vmCodeSegments) {
            LogInfo("0x%016llx - 0x%016llx (%s)",
                    (unsigned long long)segm.startVirtualAddress,
                    (unsigned long long)segm.endVirtualAddress,
                    segm.sourceName.c_str());
        }
    }
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
    const int architectureBitSize = gAssemblyInfoCmdSubparser.get<int>("--arch-bit-size");
    const addressType address = gAssemblyInfoCmdSubparser.get<addressType>("--base-address");

    ROP::AssemblySyntax inputAsmSyntax = (asmSyntaxString == "intel") ? ROP::AssemblySyntax::Intel : ROP::AssemblySyntax::ATT;
    BitSizeClass bsc = (architectureBitSize == 64) ? BitSizeClass::BIT64 : BitSizeClass::BIT32;

    InstructionConverter ic(bsc);
    ic.printCapstoneInformationForInstructions(asmInstructionsString, inputAsmSyntax, address);
}

#pragma endregion Assembly Info command


#pragma region Find Data command
#if false
int ________Find_Data_command________;
#endif

vector<pair<addressType, byteSequence>> FindByteSequenceDataTargets(const VirtualMemoryBytes& vmBytes) {
    // Get the target byte sequences from the arguments.
    vector<string> targetByteStringsVector = gFindDataCmdSubparser.get<vector<string>>("--bytes");

    // Keep only unique targets.
    set<string> targetByteStringsSet(targetByteStringsVector.begin(), targetByteStringsVector.end());

    // Parse the target byte sequences.
    vector<byteSequence> targetByteSequences;
    for (const string& bString : targetByteStringsSet) {
        assertMessage(bString.compare(0, 2, "0x") == 0,
                      "This is not a valid byte sequence (it must start with '0x'): '%s'", bString.c_str());
        if (bString.size() <= 2 || bString.size() % 2 != 0) {
           exitError("This is not a valid byte sequence (each byte must have exactly two hex letters): '%s'", bString.c_str());
        }

        byteSequence bSeq;
        for (unsigned i = 2; i < bString.size(); i += 2) {
            string currentByteLetters = bString.substr(i, 2);

            ROP::byte currentByte = 0;
            int readChars = 0;
            sscanf(currentByteLetters.c_str(), "%hhx%n", &currentByte, &readChars);
            if (readChars != 2) {
                exitError("This is not a valid hex byte: '%s'", currentByteLetters.c_str());
            }

            bSeq.push_back(currentByte);
        }

        targetByteSequences.push_back(bSeq);
    }

    using resultType = pair<addressType, byteSequence>;

    // Search for our byte sequence targets.
    vector<resultType> byteSequenceTargetResults;
    for (const byteSequence& currBytes : targetByteSequences) {
        vector<addressType> matchingAddresses = vmBytes.matchBytesInVirtualMemory(currBytes);
        for (addressType addr : matchingAddresses) {
            byteSequenceTargetResults.push_back({addr, currBytes});
        }
    }

    // Sort the results.
    auto comparator = [&](const resultType& r1, const resultType& r2) {
        if (r1.first == r2.first) {
            return r1.second.size() < r2.second.size();
        }
        return r1.first < r2.first;
    };
    sort(byteSequenceTargetResults.begin(), byteSequenceTargetResults.end(), comparator);

    return byteSequenceTargetResults;
}

vector<pair<addressType, string>> FindStringDataTargets(const VirtualMemoryBytes& vmBytes) {
    // Get the target data from the arguments.
    vector<string> targetStringsVector = gFindDataCmdSubparser.get<vector<string>>("--string");

    // Keep only unique targets.
    set<string> targetStringsSet(targetStringsVector.begin(), targetStringsVector.end());

    using resultType = pair<addressType, string>;

    // Search for our string targets.
    vector<resultType> stringTargetResults;
    for (const string& targetString : targetStringsSet) {
        vector<addressType> matchingAddresses = vmBytes.matchStringInVirtualMemory(targetString.c_str());
        for (addressType addr : matchingAddresses) {
            stringTargetResults.push_back({addr, targetString});
        }
    }

    // Sort the results.
    auto comparator = [&](const resultType& r1, const resultType& r2) {
        return r1.first < r2.first;
    };
    sort(stringTargetResults.begin(), stringTargetResults.end(), comparator);

    return stringTargetResults;
}

void DoFindDataCommand() {
    assertMessage(gFindDataCmdSubparser, "Inner logic error...");

    // Load the virtual memory byte information from the given source.
    VirtualMemoryBytes vmBytes = [&]() {
        if (auto pid = gFindDataCmdSubparser.present<int>("--process-id")) {
            return VirtualMemoryBytes(*pid);
        }
        else {
            vector<string> execs = gFindDataCmdSubparser.get<vector<string>>("--executable-path");
            vector<addressType> addrs = gFindDataCmdSubparser.get<vector<addressType>>("--base-address");
            return VirtualMemoryBytes(execs, addrs);
        }
    }();

    // Find the data.
    vector<pair<addressType, byteSequence>> byteSequenceResults = FindByteSequenceDataTargets(vmBytes);
    vector<pair<addressType, string>> stringResults = FindStringDataTargets(vmBytes);

    BitSizeClass archSize = vmBytes.getProcessArchSize();
    unsigned addressOutputSize = (archSize == BitSizeClass::BIT64) ? 16 : 8;

    // Configure the lambdas used for printing the results.
    auto printByteSequenceResult = [&](unsigned currResultIndex) {
        const auto& result = byteSequenceResults[currResultIndex];

        ostringstream ss;
        ss << std::hex << std::setfill('0');

        ss << "0x" << std::setw(addressOutputSize) << result.first << ": ";
        for (const ROP::byte& byte : result.second) {
            ss << "0x" << std::setw(2) << std::uppercase << (unsigned)byte << ' ';
        }

        const string& outputLine = ss.str();
        LogInfo("%s", outputLine.c_str());
    };
    auto printStringResult = [&](unsigned currResultIndex) {
        const auto& result = stringResults[currResultIndex];
        LogInfo("0x%0*llx: \"%s\"", addressOutputSize, result.first, result.second.c_str());
    };

    // Print the results.
    LogInfo(""); // new line

    unsigned bytesResultIndex = 0, strResultIndex = 0;
    while (bytesResultIndex < byteSequenceResults.size() && strResultIndex < stringResults.size()) {
        if (byteSequenceResults[bytesResultIndex].first < stringResults[strResultIndex].first) {
            printByteSequenceResult(bytesResultIndex++);
        }
        else {
            printStringResult(strResultIndex++);
        }
    }
    while (bytesResultIndex < byteSequenceResults.size()) {
        printByteSequenceResult(bytesResultIndex++);
    }
    while (strResultIndex < stringResults.size()) {
        printStringResult(strResultIndex++);
    }

    // Print results summary.
    LogInfo(""); // new line
    if (Log::Level::Verbose <= Log::ProgramLogLevel) {
        LogVerbose("Found %u bytes results and %u string results.",
                   (unsigned)byteSequenceResults.size(),
                   (unsigned)stringResults.size());
    }
    else {
        LogInfo("Found %u total data results.", (unsigned)(byteSequenceResults.size() + stringResults.size()));
    }
}

#pragma endregion Find Data command


#pragma region ROP Chain command
#if false
int ________ROP_Chain_command________;
#endif

void DoROPChainCommand() {
    const string ropChainType = gROPChainCmdSubparser.get<string>("--type");
    const unsigned approximateStackBufferSize = gROPChainCmdSubparser.get<unsigned>("--buffer-length");
    const unsigned maxInstructions = gROPChainCmdSubparser.get<unsigned>("--max-instructions");
    const unsigned maxInstrSeqVariants = gROPChainCmdSubparser.get<unsigned>("--max-variants");
    const unsigned maxPaddingBytesForEachInstruction = gROPChainCmdSubparser.get<unsigned>("--max-padding");
    const bool forbidNullBytes = gROPChainCmdSubparser.get<bool>("--no-null");
    const bool allowDuplicates = gROPChainCmdSubparser.get<bool>("--allow-duplicates");

    // Check that the configuration values are sensible.
    assertMessage(approximateStackBufferSize <= 100000, "Too big");
    assertMessage(1 <= maxInstructions && maxInstructions <= 100, "Please input a different number of max instructions...");
    assertMessage(maxPaddingBytesForEachInstruction <= 400, "Too big");

    // Set the preconfiguration variables.
    VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = maxInstructions;

    // Load the generator object with the information of the given source.
    PayloadGenX86 generator = [&]() {
        if (auto pid = gROPChainCmdSubparser.present<int>("--process-id")) {
            return PayloadGenX86(*pid);
        }
        else {
            vector<string> execs = gROPChainCmdSubparser.get<vector<string>>("--executable-path");
            vector<addressType> addrs = gROPChainCmdSubparser.get<vector<addressType>>("--base-address");
            return PayloadGenX86(execs, addrs);
        }
    }();

    // Configure the generator object.
    generator.forbidNullBytesInPayload = forbidNullBytes;
    generator.ignoreDuplicateInstructionSequenceResults = !allowDuplicates;
    generator.approximateByteSizeOfStackBuffer = approximateStackBufferSize;
    generator.numVariantsToOutputForEachStep = maxInstrSeqVariants;
    generator.numAcceptablePaddingBytesForOneInstruction = maxPaddingBytesForEachInstruction;
    generator.configureGenerator();

    bool success = false;
    if (ropChainType == ROPCHAIN_TYPE_SHELLNULLNULL) {
        success = generator.appendROPChainForShellCodeWithPathNullNull();
    }
    else {
        exitError("Unrecognized ROP-chain type.");
    }

    if (!success) {
        LogWarn("Can't generate the selected ROP-chain...");
        return;
    }
    LogInfo("Payload generation successful!");

    // Write output.
    int numOutputOptions = 0;
    if (gROPChainCmdSubparser.is_used("--payload-file")) {
        string payloadFile = gROPChainCmdSubparser.get<string>("--payload-file");
        generator.writePayloadToFile(payloadFile);
        LogInfo("Wrote payload bytes to \"%s\"", payloadFile.c_str());
        numOutputOptions++;
    }
    if (gROPChainCmdSubparser.is_used("--script-file")) {
        string scriptFile = gROPChainCmdSubparser.get<string>("--script-file");
        generator.writeScriptToFile(scriptFile);
        LogInfo("Wrote payload python script to \"%s\"", scriptFile.c_str());
        numOutputOptions++;
    }

    if (numOutputOptions == 0) {
        LogInfo("No output options given...");
    }
}

#pragma endregion ROP Chain command


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

    if (gFindDataCmdSubparser) {
        DoFindDataCommand();
        return 0;
    }

    if (gROPChainCmdSubparser) {
        DoROPChainCommand();
        return 0;
    }

    LogInfo("No command-line arguments. Try \"--help\"!");
    return 0;
}

#pragma endregion Main
