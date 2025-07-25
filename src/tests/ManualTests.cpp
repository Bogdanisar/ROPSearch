#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

#define PUGIXML_HEADER_ONLY
#include "../../deps/pugixml/src/pugixml.hpp"

#include "../common/utils.hpp"
#include "../ELFParser.hpp"
#include "../InstructionConverter.hpp"
#include "../PayloadGenX86.hpp"
#include "../RegisterQueryX86.hpp"
#include "../VirtualMemoryBytes.hpp"
#include "../VirtualMemoryInstructions.hpp"
#include "../VirtualMemoryMapping.hpp"


using namespace std;
using namespace ROP;


void printProcessInformation(int argc, char* argv[]) {
    int myPID = getpid();
    pv(myPID); pn;

    long pageSize = sysconf(_SC_PAGESIZE);
    pv(pageSize); pn;

    string execPath = GetAbsPathToProcExecutable();
    pv(execPath); pn;

    for (int i = 0; i < argc; ++i) {
        printf("arg[%i] = %s\n", i, argv[i]);
    }
}

void normalizeCWD() {
    string currentWorkingDirectory = filesystem::current_path();
    pv(currentWorkingDirectory); pn;

    printf("Setting CWD to the location of this binary...\n");
    SetCWDToExecutableLocation();

    currentWorkingDirectory = filesystem::current_path();
    pv(currentWorkingDirectory); pn;
}

int getPidOfExecutable(string executableName) {
    string tempFile = "pidProcess.txt";
    string command = ("pidof " + executableName + " > " + tempFile);
    int ret = system(command.c_str());
    if (ret != 0) {
        printf("System(\"%s\") failed with ret %i\n", command.c_str(), ret);
        exit(-1);
    }

    int pid;
    ifstream fin(tempFile);
    fin >> pid;
    if (!fin) {
        exitError("Failed reading the temp file with the pid...");
    }

    return pid;
}


void testVirtualMemoryMapping(int targetPid) {
    pv(targetPid); pn; pn;

    const VirtualMemoryMapping vmm(targetPid);
    printf("Segment mapping:\n");
    vmm.printMapping();
}

void testPrintCodeSegmentsOfLoadedELFs(int targetPid) {
    pv(targetPid); pn; pn;

    set<string> loadedELFs;
    const VirtualMemoryMapping vmm(targetPid);

    for (const VirtualMemorySegmentMapping& segm : vmm.getSegmentMaps()) {
        if (ELFParser::elfPathIsAcceptable(segm.path)) {
            loadedELFs.insert(segm.path);
        }
        else {
            printf("Segment without ELF file: %s\n", segm.path.c_str());
        }
    }
    printf("\n");

    printf("___________ Printing code-segment information about the loaded ELFs ___________\n");
    for (const string& elfPath : loadedELFs) {
        assert(ELFParser::elfPathIsAcceptable(elfPath));

        printf("ELF file: %s\n", elfPath.c_str());

        ELFParser parser(elfPath);
        auto fileHeader = parser.getFileHeader();

        printf("e_ident: ");
        for (int i = 0; i < EI_NIDENT; ++i) {
            printf("%hhX ", fileHeader.e_ident[i]);
        }

        printf("(");
        for (int i = 0; i < EI_NIDENT; ++i) {
            char c = isprint(fileHeader.e_ident[i]) ? fileHeader.e_ident[i] : '.';
            printf("%c", c);
        }
        printf(")\n");

        printf("Segment Table offset: %llu; Segment header size: %llu; Segment header number: %llu\n",
                (long long unsigned)fileHeader.e_phoff, (long long unsigned)fileHeader.e_phentsize, (long long unsigned)fileHeader.e_phnum);

        printf("Code segments:\nOffset             VirtAddr           PhysAddr           FileSiz            MemSiz             Flags  Align\n");
        auto codeSegmentHeaders = parser.getCodeSegmentHeaders();
        for (size_t i = 0; i < codeSegmentHeaders.size(); ++i) {
            const Elf64_Phdr& hdr = codeSegmentHeaders[i];
            bool isReadable = ((hdr.p_flags & PF_R) != 0);
            bool isWritable = ((hdr.p_flags & PF_W) != 0);
            bool isExecutable = ((hdr.p_flags & PF_X) != 0);

            printf("%#018llx %#018llx %#018llx %#018llx %#018llx %c%c%c    %#018llx\n",
                   (unsigned long long)hdr.p_offset,
                   (unsigned long long)hdr.p_vaddr,
                   (unsigned long long)hdr.p_paddr,
                   (unsigned long long)hdr.p_filesz,
                   (unsigned long long)hdr.p_memsz,
                   isReadable ? 'R' : ' ',
                   isWritable ? 'W' : ' ',
                   isExecutable ? 'E' : ' ',
                   (unsigned long long)hdr.p_align);
        }
        printf("\n");

        printf("\n");
    }
}

void testVirtualMemoryBytes(string targetExecutable) {
    pv(targetExecutable); pn;

    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn; pn;

    VirtualMemoryBytes vmBytes(targetPid);
    const vector<VirtualMemorySegmentBytes>& segments = vmBytes.getReadSegments();

    printf("Executable Virtual Memory ranges (plus a few bytes from the start of the segment):\n");
    for (const auto& segm : segments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        addressType start = segm.startVirtualAddress;
        addressType end = segm.endVirtualAddress;
        addressType actualEnd = start + (unsigned long long)segm.bytes.size();
        printf("0x%llx-0x%llx (real: 0x%llx-0x%llx; sz: 0x%08llx): ",
               start, end, start, actualEnd, (unsigned long long)segm.bytes.size());

        size_t bytesToPrint = min((size_t)20, segm.bytes.size());
        for (size_t i = 0; i < bytesToPrint; ++i) {
            printf("%02hhx ", segm.bytes[i]);
        }
        printf("...\n");
    }
    printf("\n");

    if (segments.size() != 0) {
        const auto& firstSegm = segments[0];
        addressType firstSegmStart = firstSegm.startVirtualAddress;
        size_t bytesToPrint = min((size_t)20, firstSegm.bytes.size());

        printf("Testing VirtualMemoryBytes::getByteAtVirtualAddress():\n");
        for (addressType addr = firstSegmStart; addr < firstSegmStart + bytesToPrint; ++addr) {
            ROP::byte b = vmBytes.getByteAtVirtualAddress(addr);
            printf("virtual_memory[0x%llx] = %02hhx\n", addr, b);
        }
    }
}

void testVirtualMemoryBytesFindMatchingBytes(string targetExecutable) {
    pv(targetExecutable); pn;

    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    // Print the Virtual Memory ranges of executable bytes in the target process.
    testVirtualMemoryMapping(targetPid); pn;

    // Get the virtual memory bytes of the target process.
    VirtualMemoryBytes vmBytes(targetPid);

    // Convert the target string to a byte sequence.
    // const char * const targetString = "H=";
    const char * const targetString = "/bin/sh";
    // const char * const targetString = "exit 0";

    // Get the output size of each address;
    BitSizeClass bsc = vmBytes.getProcessArchSize();
    unsigned addrOutputSize = (bsc == BitSizeClass::BIT64) ? 16 : 8;

    printf("Found matching bytes in memory:\n");
    vector<addressType> vmAddresses = vmBytes.matchStringInVirtualMemory(targetString);
    for (const addressType& addr : vmAddresses) {
        printf("0x%0*llx: \"%s\"\n", addrOutputSize, addr, targetString);
    }
}

void testGetExecutableBytesInteractive(string targetExecutable) {
    pv(targetExecutable); pn;

    // You need to start the target executable (under GDB) before running this.
    // And, while both are running, compare the output of this with the output of GDB:
    // $> gdb ./target.exe
    // (gdb) break main
    // (gdb) start
    // (gdb) x/20bx main
    // (gdb) x/20bx printf
    // ...
    // (gdb) kill
    // They should show the same bytes in memory for valid virtual addresses.

    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    // Print the Virtual Memory ranges of executable bytes in the target process.
    testVirtualMemoryMapping(targetPid); pn;
    testVirtualMemoryBytes(targetExecutable); pn;

    VirtualMemoryBytes vmBytes(targetPid);

    printf("Interactive virtual memory inspector...\n");
    while (true) {
        long long addr;
        printf("Please input a virtual memory address (or 0 to exit): ");
        int numMatched = scanf("%lli", &addr);
        if (numMatched != 1) {
            printf("Bad input...\n\n");
            char c;
            while (scanf("%c", &c) == 1) {
                if (c == '\n') {
                    break;
                }
            }
            continue;
        }

        if (addr == 0) {
            printf("Done...\n");
            break;
        }

        for (addressType cAddr = addr; cAddr < (addressType)addr + 20; ++cAddr) {
            if (!vmBytes.isValidVirtualAddress(cAddr)) {
                printf("Address not in virtual memory...\n");
                break;
            }

            ROP::byte b = vmBytes.getByteAtVirtualAddress(cAddr);
            printf("virtual_memory[0x%llx] = 0x%02hhx\n", cAddr, b);
        }
        printf("\n");
    }
}

void testKeystoneFrameworkIntegration() {
    // Using AT&T syntax for the instructions below.
    ROP::AssemblySyntax syntax = ROP::AssemblySyntax::ATT;

    // A few arbitrary instructions.
    vector<string> instructionSequences = {
        // First element
        "xor %rcx, %rcx",

        // Second element
        "sub %rbx, %rcx",

        // Third element
        "mov (%r10), %r10; "
        "mov (%r8), %r8; "
        "mov (%r9), %r9",

        // Fourth element
        "nop; "
        "pop %rax; "
        "syscall; "
        "pop %r10; "
        "mov %rax, (%r10)",
    };

    InstructionConverter ic;
    ic = InstructionConverter(BitSizeClass::BIT64); // Test the move assignment operator.

    for (const string& insSeq : instructionSequences) {
        auto result = ic.convertInstructionSequenceToBytes(insSeq, syntax);
        const byteSequence& byteSeq = result.first;
        unsigned numDecodedInstructions = result.second;

        printf("Instructions: %s\n", insSeq.c_str());
        printf("Decoded %u instructions into %u bytes: ", numDecodedInstructions, (unsigned)byteSeq.size());
        for (const ROP::byte& b : byteSeq) {
            printf("%02hhX ", (unsigned char)b);
        }
        printf("\n\n");
    }
}

void testCapstoneFrameworkIntegration() {
    InstructionConverter ic;
    ic = InstructionConverter(BitSizeClass::BIT64); // Test the move assignment operator.

    // byteSequence bytes = {
    //     // "endbr64" instruction:
    //     (ROP::byte)'\xF3',
    //     (ROP::byte)'\x0F',
    //     (ROP::byte)'\x1E',
    //     (ROP::byte)'\xFA',

    //     // junk:
    //     (ROP::byte)'\xFF',
    //     (ROP::byte)'\xFF',
    // };

    byteSequence bytes = {
        // "gs" segment prefix:
        0x65,

        // relative "call" opcode:
        0xE8,

        // address offset:
        0x5B,
        0x41,
    	0x5C,
        0x41,
    };

    // Disassemble these bytes into assembly instructions as strings;
    vector<string> instructions;
    unsigned disassembledBytes;
    disassembledBytes = ic.convertInstructionSequenceToString(bytes,
                                                              ROP::AssemblySyntax::Intel,
                                                              0,
                                                              0,
                                                              &instructions);

    printf("Number of input bytes: %u\n", (unsigned)bytes.size());
    printf("Number of disassembled bytes: %u\n", disassembledBytes);

    printf("Disassembled instructions:\n");
    for (size_t i = 0; i < instructions.size(); ++i) {
        printf("instr[%i] = %s\n", (int)i, instructions[i].c_str());
    }
}

// The point of this function is to see how
// direct JMP instructions are byte-encoded in x86 and x64.
// (direct JMP instructions have a hardcoded relative offset or absolute address)
// (indirect JMP instructions get their info from a register or a memory location)
void testCapstoneConvertBytesOfDirectJMPInstructions() {
    vector<BitSizeClass> instrConverters = {
        BitSizeClass::BIT32,
        BitSizeClass::BIT64,
    };

    vector<byteSequence> inputBytesList = {
        {
            // "JMP rel8" instruction.
            0xEB, // opcode
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        },
        {
            // "JMP rel16" / "JMP rel32" instruction.
            0xE9, // opcode
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        },
        {
            // "JMP ptr16:16" /  "JMP ptr16:32" instruction.
            0xEA, // opcode
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            0x07,
            0x08,
        }
    };

    printf("Trying to disassemble each byte sequence and stopping at the first disassembled instruction...\n\n");

    for (const BitSizeClass& bsc : instrConverters) {
        printf("_____________ Arch bit size: %i _____________\n", bsc == BitSizeClass::BIT64 ? 64 : 32);
        InstructionConverter ic(bsc);

        for (byteSequence& originalBytes: inputBytesList) {

            auto lambda = [&](byteSequence bytes, bool addPrefixByte) {
                if (!addPrefixByte) {
                    printf("Current bytes:\n");
                }
                else {
                    // Add the operand-size override prefix byte (0x66) at the start.
                    // This can change the byte-size of the value placed after the opcode.
                    bytes.insert(bytes.begin(), 0x66);
                    printf("Current bytes (with operand-size override prefix byte):\n");
                }

                printf("    ");
                for (const ROP::byte byte : bytes) {
                    printf("0x%02hhX ", byte);
                }
                printf("\n");

                // Disassemble these bytes and stop at the first disassembled instruction.
                vector<string> instructions;
                unsigned disassembledBytes;
                disassembledBytes = ic.convertInstructionSequenceToString(bytes,
                                                                        ROP::AssemblySyntax::Intel,
                                                                        0,
                                                                        1,
                                                                        &instructions);

                printf("Number of disassembled bytes: %u\n", disassembledBytes);
                printf("Disassembled bytes: ");
                for (unsigned idx = 0; idx < disassembledBytes; ++idx) {
                    printf("0x%02hhX ", bytes[idx]);
                }
                printf("\n");

                printf("Disassembled instructions:\n");
                for (size_t i = 0; i < instructions.size(); ++i) {
                    printf("    instr[%i] = %s\n", (int)i, instructions[i].c_str());
                }
            };

            lambda(originalBytes, false);
            printf("\n");

            lambda(originalBytes, true);
            printf("\n");
        }
    }
}

void testCapstoneGetRegisterInfo() {
    InstructionConverter ic(BitSizeClass::BIT64);

    vector<byteSequence> byteSequences = {
        {
            // "endbr64" instruction:
            (ROP::byte)'\xF3',
            (ROP::byte)'\x0F',
            (ROP::byte)'\x1E',
            (ROP::byte)'\xFA',

            // junk:
            (ROP::byte)'\xFF',
            (ROP::byte)'\xFF',
        },

        {
            // "gs" segment prefix:
            0x65,

            // relative "call" opcode:
            0xE8,

            // address offset:
            0x5B,
            0x41,
            0x5C,
            0x41,
        },

        {
            // "xor %rax, %rax" instruction:
            (ROP::byte)'\x48',
            (ROP::byte)'\x31',
            (ROP::byte)'\xC0',
        },

        {
            // "xor %rcx, %rcx" instruction:
            (ROP::byte)'\x48',
            (ROP::byte)'\x31',
            (ROP::byte)'\xC9',
        },

        {
            // "nop; pop %rax; syscall; pop %r10; mov %rax, (%r10)"
            (ROP::byte)'\x90',
            (ROP::byte)'\x58',
            (ROP::byte)'\x0F',
            (ROP::byte)'\x05',
            (ROP::byte)'\x41',
            (ROP::byte)'\x5A',
            (ROP::byte)'\x49',
            (ROP::byte)'\x89',
            (ROP::byte)'\x02',
        },

        {
            (ROP::byte)'\xC3',
        }
    };

    for (const byteSequence& bytes : byteSequences) {
        // Disassemble these bytes into assembly instructions as strings;
        vector<string> instructions;
        vector<RegisterInfo> regInfo;
        unsigned disassembledBytes;
        disassembledBytes = ic.convertInstructionSequenceToString(bytes,
                                                                  ROP::AssemblySyntax::Intel,
                                                                  0,
                                                                  0,
                                                                  &instructions,
                                                                  &regInfo);
        assert(instructions.size() == regInfo.size());

        printf("Number of input bytes: %u\n", (unsigned)bytes.size());
        printf("Number of disassembled bytes: %u\n", disassembledBytes);

        printf("Disassembled instructions:\n");
        for (size_t i = 0; i < instructions.size(); ++i) {
            printf("instr[%i] = %s\n", (int)i, instructions[i].c_str());

            printf("Read registers: ");
            for (unsigned regIndex = 0; regIndex < (unsigned)X86_REG_ENDING; ++regIndex) {
                if (regInfo[i].rRegs.test(regIndex)) {
                    printf("%s ", InstructionConverter::convertCapstoneRegIdToString((x86_reg)regIndex));
                }
            }
            printf("\n");

            printf("Written registers: ");
            for (unsigned regIndex = 0; regIndex < (unsigned)X86_REG_ENDING; ++regIndex) {
                if (regInfo[i].wRegs.test(regIndex)) {
                    printf("%s ", InstructionConverter::convertCapstoneRegIdToString((x86_reg)regIndex));
                }
            }
            printf("\n");

            printf("\n");
        }

        printf("\n");
    }

    LogVar(InstructionConverter::convertCapstoneRegIdToString(X86_REG_RAX)); LogLine();
    LogVar(InstructionConverter::convertCapstoneRegIdToString(X86_REG_R15)); LogLine();
    LogVar(InstructionConverter::convertCapstoneRegIdToString(X86_REG_EFLAGS)); LogLine();

    LogVar(InstructionConverter::convertRegShortStringToCapstoneRegId("rax")); LogLine();
    LogVar(InstructionConverter::convertRegShortStringToCapstoneRegId("bl")); LogLine();
    LogVar(InstructionConverter::convertRegShortStringToCapstoneRegId("r13")); LogLine();
}

void testKeystoneCapstoneFrameworkIntegration() {
    // Using AT&T syntax for the instructions below.
    ROP::AssemblySyntax syntax = ROP::AssemblySyntax::ATT;

    // A few arbitrary instructions.
    vector<string> instructionSequences = {
        // First element
        "xor %rcx, %rcx",

        // Second element
        "sub %rbx, %rcx",

        // Third element
        "mov (%r10), %r10; "
        "mov (%r8), %r8; "
        "mov (%r9), %r9",

        // Fourth element
        "nop; "
        "pop %rax; "
        "syscall; "
        "pop %r10; "
        "mov %rax, (%r10)",

        // 5th element
        "add %cl, %ch; ret",
    };

    InstructionConverter ic(BitSizeClass::BIT64);
    for (const string& originalInsSeq : instructionSequences) {
        printf("Original instructions: %s\n", originalInsSeq.c_str());


        // Decode the original instruction sequence (string) into bytes;
        auto originalResult = ic.convertInstructionSequenceToBytes(originalInsSeq, syntax);
        const byteSequence& originalByteSeq = originalResult.first;
        unsigned originalNumDecodedInstructions = originalResult.second;

        printf("Decoded %u instructions into %u bytes: ", originalNumDecodedInstructions, (unsigned)originalByteSeq.size());
        for (const ROP::byte& b : originalByteSeq) {
            printf("%02hhX ", (unsigned char)b);
        }
        printf("\n");


        // Encode these bytes back into instructions as strings;
        vector<string> newInstructions;
        unsigned disassembledBytes;
        disassembledBytes = ic.convertInstructionSequenceToString(originalByteSeq, syntax, 0, 0, &newInstructions);
        assert(disassembledBytes != 0);
        UNUSED(disassembledBytes); // So that assert-less compilations don't show a warning.

        printf("Re-encoded instructions:\n");
        for (size_t i = 0; i < newInstructions.size(); ++i) {
            printf("    instr[%i] = %s\n", (int)i, newInstructions[i].c_str());
        }


        // Decode the new instruction string back into bytes;
        string newInstructionSequenceAsm = "";
        for (size_t i = 0; i < newInstructions.size(); ++i) {
            newInstructionSequenceAsm += newInstructions[i];
            if (i != newInstructions.size() - 1) {
                newInstructionSequenceAsm += "; ";
            }
        }

        auto newResult = ic.convertInstructionSequenceToBytes(newInstructionSequenceAsm, syntax);
        const byteSequence& newByteSeq = newResult.first;
        unsigned newNumDecodedInstructions = newResult.second;

        printf("Re-decoded %u instructions into %u bytes: ", newNumDecodedInstructions, (unsigned)newByteSeq.size());
        for (const ROP::byte& b : newByteSeq) {
            printf("%02hhX ", (unsigned char)b);
        }
        printf("\n\n");
    }
}

void testInstructionNormalization() {
    InstructionConverter ic(BitSizeClass::BIT64);

    // These are some sample instruction sequences found in libc.so.6
    // Note: Using Intel syntax for the instructions below.
    vector<string> instructionSequencesIntel = {
        "add CH, CL ; ret",
        "and WORD PTR [RDI], SP ; ret",
        "dec DWORD PTR [RAX - 0X77] ; ret 0X840F",
        "mov ECX, EAX ; mov EAX, ECX ; ret",
        "mov EDX, 0XFFFFFFFF ; ret",
        "or AL, 0X7E ; ret",
        "push 0 ; push 0 ; call 0X1515F0",
        "sub EAX, ESI ; ret",
        "xchg EAX, EBP ; ret 0XFFFF",
        "xor RAX, RAX ; ret"
    };

    printf("//////////////////// Normalizing Intel-assembly instructions ////////////////////\n");
    for (const string& insAsm : instructionSequencesIntel) {
        const vector<string>& normalizedInstructions = ic.normalizeInstructionAsm(insAsm,
                                                                                  ROP::AssemblySyntax::Intel,
                                                                                  ROP::AssemblySyntax::Intel);
        const string& normalizedInsAsm = ic.concatenateInstructionsAsm(normalizedInstructions);
        printf("insAsm = %s\n", insAsm.c_str());
        printf("normalizedInsAsm = %s\n", normalizedInsAsm.c_str());
    }


    // A few arbitrary instructions.
    // Note: Using AT&T syntax for the instructions below.
    vector<string> instructionSequencesATT = {
        // First element
        "xor %rcx, %rcx",

        // Second element
        "sub %rbx, %rcx",

        // Third element
        "mov (%r10), %r10; "
        "mov (%r8), %r8; "
        "mov (%r9), %r9",

        // Fourth element
        "nop; "
        "pop %rax; "
        "syscall; "
        "pop %r10; "
        "mov %rax, (%r10)",

        // 5th element
        "add %cl, %ch; ret",
    };

    printf("\n");

    printf("//////////////////// Normalizing AT&T-assembly instructions ////////////////////\n");
    for (const string& insAsm : instructionSequencesATT) {
        const vector<string>& normalizedInstructions = ic.normalizeInstructionAsm(insAsm,
                                                                                  ROP::AssemblySyntax::ATT,
                                                                                  ROP::AssemblySyntax::Intel);
        const string& normalizedInsAsm = ic.concatenateInstructionsAsm(normalizedInstructions);
        printf("insAsm = %s\n", insAsm.c_str());
        printf("normalizedInsAsm = %s\n", normalizedInsAsm.c_str());
    }
}

void testFindingInstructionSequenceInMemory(string targetExecutable) {
    // You need to start the target executable (under GDB) before running this.
    // And then compare the output of this function with the output of GDB:
    // $> gdb ./vulnerable64bit.exe
    // (gdb) set disassembly-flavor intel
    // (gdb) break main
    // (gdb) start
    // (gdb) x/10i yourAddressHere
    // ...
    // (gdb) kill
    // You should see in gdb your instruction sequence at the virtual address(es) given by this function.

    pv(targetExecutable); pn;
    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    // Print the Virtual Memory mapping of the target process.
    testVirtualMemoryMapping(targetPid); pn;

    VirtualMemoryInstructions vmInfo;
    vmInfo = VirtualMemoryInstructions(targetPid); // Test the move assignment operator.
    printf("Finished initializing vmInfo object!\n\n");

    // These are some sample instruction sequences found in libc.so.6
    // Note: Using Intel syntax here.
    ROP::AssemblySyntax syntax = ROP::AssemblySyntax::Intel;
    vector<string> instructionSequences = {
        "add ch, cl ; ret",
        "and word ptr [rdi], sp ; ret",
        "dec dword ptr [rax - 0x77] ; ret 0x840f",
        "mov ecx, eax ; mov eax, ecx ; ret",
        "mov edx, 0xffffffff ; ret",
        "or al, 0x7e ; ret",
        "sub eax, esi ; ret",
        "xchg eax, ebp ; ret 0xffff",
        "xor rax, rax ; ret"
    };

    InstructionConverter ic(BitSizeClass::BIT64);

    printf("======= Searching for instruction sequences in virtual memory... =======\n");
    for (const string& insSeq : instructionSequences) {
        printf("Instruction sequence: %s\n", insSeq.c_str());

        auto normalizedArray = ic.normalizeInstructionAsm(insSeq, AssemblySyntax::Intel, ROP::AssemblySyntax::Intel);
        auto normalizedString = ic.concatenateInstructionsAsm(normalizedArray);
        printf("Normalized instruction sequence: %s\n", normalizedString.c_str());

        vector<addressType> matchedAddresses = vmInfo.matchInstructionSequenceInVirtualMemory(insSeq, syntax);
        if (matchedAddresses.size() != 0) {
            for (addressType addr : matchedAddresses) {
                printf("Found at 0x%llx\n", addr);
            }
        }
        else {
            printf("Didn't find this instruction sequence in virtual memory...\n");
        }
        printf("\n");
    }
}

void printVMInstructionSequences(string targetExecutable) {
    pv(targetExecutable); pn;
    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    // Print the Virtual Memory mapping of the target process.
    testVirtualMemoryMapping(targetPid); pn;

    VirtualMemoryInstructions vmInfo(targetPid);
    printf("Finished initializing vmInfo object!\n\n");

    InstructionConverter ic(BitSizeClass::BIT64);

    printf("Found instruction sequences:\n");
    auto instrSeqs = vmInfo.getInstructionSequences();
    for (const auto& p : instrSeqs) {
        addressType addr = p.first;
        string fullSequence = ic.concatenateInstructionsAsm(p.second);
        printf("0x%10llx: %s\n", addr, fullSequence.c_str());
    }
}

void testFilterVMInstructionSequencesByRegisterInfo(string targetExecutable) {
    pv(targetExecutable); pn;
    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    VirtualMemoryInstructions::computeRegisterInfo = true;
    VirtualMemoryInstructions vmInfo(targetPid);
    printf("Finished initializing vmInfo object!\n\n");

    InstructionConverter ic(BitSizeClass::BIT64);

    vector<vector<RegisterInfo>> allRegInfoSeqs;
    auto instrSeqs = vmInfo.getInstructionSequences(&allRegInfoSeqs);
    assert(instrSeqs.size() == allRegInfoSeqs.size());
    LogVar(instrSeqs.size()); LogLine(); LogLine();
    unsigned long long numMatching = 0;

    printf("Found instruction sequences:\n");
    for (unsigned idx = 0; idx < instrSeqs.size(); ++idx) {
        addressType addr = instrSeqs[idx].first;
        const vector<string>& currInstrSeq = instrSeqs[idx].second;
        const vector<RegisterInfo>& currRegInfoSeq = allRegInfoSeqs[idx];
        assert(currInstrSeq.size() == currRegInfoSeq.size());

        // Keep only instruction sequences that manipulate the target registers.
        bool match = false;
        for (const RegisterInfo& regInfo : currRegInfoSeq) {
            // LogVar(regInfo.rRegs.count()); LogLine();
            // for (unsigned regId = 0; regId < (unsigned)X86_REG_ENDING; ++regId) {
            //     if (regInfo.rRegs[regId]) {
            //         LogDebug("Read register: %s", InstructionConverter::convertCapstoneRegIdToString((x86_reg)regId));
            //     }
            // }

            // LogVar(regInfo.wRegs.count()); LogLine();

            if (regInfo.rRegs[X86_REG_RBX] && regInfo.wRegs[X86_REG_DH]) {
                match = true;
                break;
            }
        }

        if (match) {
            numMatching += 1;
            string fullSequence = ic.concatenateInstructionsAsm(currInstrSeq);
            printf("0x%10llx: %s\n", addr, fullSequence.c_str());
        }

        // LogLine();
    }

    LogVar(numMatching); LogLine();
}

void testXMLReading() {
    using namespace pugi;

    const char * const source =
        "<shape name='square'>"
            "<size>5</size>"
            "<lower-left x='3' y='10'></lower-left>"
        "</shape>";
    xml_document doc;
    xml_parse_result loadResult = doc.load_string(source);
    if (!loadResult) {
        exitError("Got error loading the XML string: %s", loadResult.description());
    }

    printf("XML document loaded!\n");
    printf("Value of entire XML document: \n%s\n", XmlNodeToString(doc).c_str());

    xml_node shape = doc.child("shape");

    const char * const name = shape.attribute("name").value();
    int size = shape.child("size").text().as_int();
    pv(name);pn;
    pv(size);pn;

    int lowerLeftX = shape.child("lower-left").attribute("x").as_int();
    int lowerLeftY = shape.child("lower-left").attribute("y").as_int();
    pv(lowerLeftX);pn;
    pv(lowerLeftY);pn;
}

void testLoggingFunctionality() {
    printf("Logging with default level:\n");
    LogDebug("Debug flag: %i\n", (int)Log::Level::Debug);
    LogVerbose("Verbose flag: %i\n", (int)Log::Level::Verbose);
    LogInfo("Info flag: %i\n", (int)Log::Level::Info);
    LogWarn("Warn flag: %i\n", (int)Log::Level::Warn);
    LogError("Error flag: %i\n\n", (int)Log::Level::Error);

    Log::ProgramLogLevel = Log::Level::Debug;

    printf("Logging with changed level:\n");
    LogDebug("Debug flag: %i\n", (int)Log::Level::Debug);
    LogVerbose("Verbose flag: %i\n", (int)Log::Level::Verbose);
    LogInfo("Info flag: %i\n", (int)Log::Level::Info);
    LogWarn("Warn flag: %i\n", (int)Log::Level::Warn);
    LogError("Error flag: %i\n", (int)Log::Level::Error);
}

void testBytesOfInteger() {
    LogDebug("Integer: %hhu", (unsigned char)0b01110111);
    for (auto b : BytesOfInteger((unsigned char)0b01110111)) {
        LogVar((int)b); LogLine();
    }
    LogLine();

    LogDebug("Integer: %llu", (unsigned long long)213234523);
    for (auto b : BytesOfInteger((unsigned long long)213234523)) {
        LogVar((int)b); LogLine();
    }
    LogLine();
}

void testLoadVirtualMemoryOfExecutablePaths() {
    vector<string> execPaths = {
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
    };
    vector<addressType> baseAddresses = {
        // 0x7ffff7c28000,
        // 0x7ffff7fc6000,
    };
    VirtualMemoryInstructions vmInfo(execPaths, baseAddresses);

    // These are some sample instruction sequences found in libc.so.6
    // Note: Using Intel syntax here.
    ROP::AssemblySyntax syntax = ROP::AssemblySyntax::Intel;
    vector<string> instructionSequences = {
        "add ch, cl ; ret",
        "and word ptr [rdi], sp ; ret",
        "dec dword ptr [rax - 0x77] ; ret 0x840f",
        "mov ecx, eax ; mov eax, ecx ; ret",
        "mov edx, 0xffffffff ; ret",
        "or al, 0x7e ; ret",
        "sub eax, esi ; ret",
        "xchg eax, ebp ; ret 0xffff",
        "xor rax, rax ; ret"
    };

    InstructionConverter ic(BitSizeClass::BIT64);

    printf("======= Searching for instruction sequences in virtual memory... =======\n");
    for (const string& insSeq : instructionSequences) {
        printf("Instruction sequence: %s\n", insSeq.c_str());

        auto normalizedArray = ic.normalizeInstructionAsm(insSeq, AssemblySyntax::Intel, ROP::AssemblySyntax::Intel);
        auto normalizedString = ic.concatenateInstructionsAsm(normalizedArray);
        printf("Normalized instruction sequence: %s\n", normalizedString.c_str());

        vector<addressType> matchedAddresses = vmInfo.matchInstructionSequenceInVirtualMemory(insSeq, syntax);
        if (matchedAddresses.size() != 0) {
            for (addressType addr : matchedAddresses) {
                printf("Found at 0x%llx\n", addr);
            }
        }
        else {
            printf("Didn't find this instruction sequence in virtual memory...\n");
        }
        printf("\n");
    }
}

void testRegisterQueryTransformation() {
    RegisterQueryX86 basicRQ("read(RAX)");

    // Print precomputed basic operator strings.
    for (const auto& regOperatorInfo : basicRQ.registerTermStrings) {
        const x86_reg& regID = regOperatorInfo.regID;
        const char *regCString = ROP::InstructionConverter::convertCapstoneRegIdToString(regID);
        const std::string& termString = regOperatorInfo.termString;

        LogVar(termString); LogDebug("(reg = %s)", regCString);
    }
    LogLine();

    vector<string> queryList = {
        "TRUE | false & READ(edi)",
        "!!!(read(RAX) | read(dh))   &  (write(ebX) ^ write(ecx)) ",
        "!!!read(RAX) ^ !!write(RBX) ^ !write(RCX)",
        "!(((( write(ah) & write(bh) & WRITE(ch) & (write(DH)) ))))",
        "read(RAX)  ((((",
        "read(RAX)  ))))",
    };
    for (const string& query : queryList) {
        RegisterQueryX86 rq(query);

        LogDebug("Initial query: %s", query.c_str());
        LogDebug("Transformed query: %s", rq.queryCString);
        LogDebug("Query representation: %s", rq.getStringRepresentationOfQuery().c_str());
        LogLine();
    }
}

void testBinaryRepresentationOfInteger() {
    pv(GetBinaryReprOfInteger((long long)19)); pn;
    pv(GetBinaryReprOfInteger((int)19)); pn;
    pv(GetBinaryReprOfInteger((short int)19)); pn;
    pv(GetBinaryReprOfInteger((unsigned char)19)); pn;
}

void testMinimumNumberOfBytesToStoreInteger() {
    pv(GetMinimumNumberOfBytesToStoreInteger(0)); pn;
    pv(GetMinimumNumberOfBytesToStoreInteger(36)); pn;
    pv(GetMinimumNumberOfBytesToStoreInteger(255)); pn;
    pv(GetMinimumNumberOfBytesToStoreInteger(256)); pn;
    pv(GetMinimumNumberOfBytesToStoreInteger(1024)); pn;
    pv(GetMinimumNumberOfBytesToStoreInteger(1<<15)); pn;
    pv(GetMinimumNumberOfBytesToStoreInteger(1<<16)); pn;
}

void testShowCapstoneInstructionInfo() {
    auto instrSeqStr = "rol byte ptr [rdx - 0x76b60002], cl; ret; add rax, rbx; add [rax], rbx";
    // auto instrSeqStr = "rol byte ptr [rdx - 0x76b60002], cl";
    // auto instrSeqStr = "stosq qword ptr [rdi], rax;";
    // auto instrSeqStr = "rep stosq qword ptr [rdi], rax";
    // auto instrSeqStr = "add r8, r9; stosq";
    // auto instrSeqStr = "mov qword ptr [rax + 2*rbx], rcx";
    // auto instrSeqStr = "ret; add rax, 0x12; add rax, 0x1234; add rax, 0x12345678; mov rax, 0x123456789ABCDEF0";
    // auto instrSeqStr = "ret; add rax, 0x12; mov rax, 0x123456789ABCDEF0; mov qword ptr [rax], 0x12";
    // auto instrSeqStr = "ret; add ah, 0x12; mov ax, 0xDEF0; mov dword ptr [rax], 0x12; xor ax, bx";

    InstructionConverter ic(BitSizeClass::BIT64);
    ic.printCapstoneInformationForInstructions(instrSeqStr, AssemblySyntax::Intel);
}

// Note: These macros might not be available for all architectures.
void testEndianness() {
    #if defined(__BYTE_ORDER) && __BYTE_ORDER == __LITTLE_ENDIAN || \
        defined(__LITTLE_ENDIAN)
        printf("Little endian program!\n");
    #elif defined(__BYTE_ORDER) && __BYTE_ORDER == __BIG_ENDIAN || \
          defined(__BIG_ENDIAN__)
        printf("Big endian program!\n");
    #else
        #error "I do not know what endianness this program is."
    #endif
}

void testConvertBytesToIntFunction() {
    {
        vector<ROP::byte> bytes = {0xFF, 0xFF, 0xFF, 0xFF};
        printf("int8_t: %hhi\n", ConvertLittleEndianBytesToInteger<int8_t>(bytes.data()));
        printf("int16_t: %hi\n", ConvertLittleEndianBytesToInteger<int16_t>(bytes.data()));
        printf("int32_t: %i\n", ConvertLittleEndianBytesToInteger<int32_t>(bytes.data()));
    }

    {
        vector<ROP::byte> bytes = {0x01, 0x01, 0x01, 0x01};
        printf("int8_t: %hhi\n", ConvertLittleEndianBytesToInteger<int8_t>(bytes.data()));
        printf("int16_t: %hi\n", ConvertLittleEndianBytesToInteger<int16_t>(bytes.data()));
        printf("int32_t: %i\n", ConvertLittleEndianBytesToInteger<int32_t>(bytes.data()));
    }

    printf("int: %i\n", (1 << 31));
}

void testPayloadGeneration() {
    string targetExecutable = "vulnerable32bit.exe";
    // string targetExecutable = "vulnerable64bit.exe";
    pv(targetExecutable); pn;

    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    PayloadGenX86 generator(targetPid);
    generator.forbidNullBytesInPayload = false;
    generator.ignoreDuplicateInstructionSequenceResults = true;
    generator.approximateByteSizeOfStackBuffer = 100;
    generator.numVariantsToOutputForEachStep = 0; // all of them.
    generator.numAcceptablePaddingBytesForOneInstruction = 400;
    generator.configureGenerator();

    // generator.appendGadgetForCopyOrExchangeRegisters(X86_REG_RAX, X86_REG_RDX, {});
    // generator.appendGadgetForCopyOrExchangeRegisters(X86_REG_RBX, X86_REG_RAX, {X86_REG_RAX});

    // generator.appendGadgetForAssignValueToRegister(X86_REG_RAX, 0x00112233, {});
    // generator.appendGadgetForAssignValueToRegister(X86_REG_RBX, 0x11223344, {});
    // generator.appendGadgetForAssignValueToRegister(X86_REG_RCX, -1, {});

    generator.appendROPChainForShellCodeWithPathNullNull();

    generator.writePayloadToFile("_payload.dat");
    generator.writeScriptToFile("_payloadScript.py");
}


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    Log::ProgramLogLevel = Log::Level::Debug;
    // Log::ProgramLogLevel = Log::Level::Info;

    printProcessInformation(argc, argv); pn;
    normalizeCWD(); pn;

    // testVirtualMemoryMapping(getpid()); pn;
    // testPrintCodeSegmentsOfLoadedELFs(getpid()); pn;
    // testVirtualMemoryBytes("vulnerable64bit.exe"); pn;
    // testVirtualMemoryBytesFindMatchingBytes("vulnerable64bit.exe"); pn;
    // testGetExecutableBytesInteractive("vulnerable64bit.exe"); pn;
    // testKeystoneFrameworkIntegration(); pn;
    // testCapstoneFrameworkIntegration(); pn;
    // testCapstoneConvertBytesOfDirectJMPInstructions(); pn;
    // testCapstoneGetRegisterInfo(); pn;
    // testKeystoneCapstoneFrameworkIntegration(); pn;
    // testInstructionNormalization(); pn;
    // testFindingInstructionSequenceInMemory("vulnerable64bit.exe"); pn;
    // printVMInstructionSequences("vulnerable64bit.exe"); pn;
    // testFilterVMInstructionSequencesByRegisterInfo("vulnerable64bit.exe"); pn;
    // testXMLReading();pn;
    // testLoggingFunctionality(); pn;
    // testBytesOfInteger(); pn;
    // testLoadVirtualMemoryOfExecutablePaths(); pn;
    // testRegisterQueryTransformation(); pn;
    // testBinaryRepresentationOfInteger(); pn;
    // testMinimumNumberOfBytesToStoreInteger(); pn;
    // testShowCapstoneInstructionInfo(); pn;
    // testEndianness(); pn;
    // testConvertBytesToIntFunction(); pn;
    testPayloadGeneration(); pn;

    return 0;
}
