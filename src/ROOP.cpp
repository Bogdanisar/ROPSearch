#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

#include "common/utils.hpp"
#include "ELFParser.hpp"
#include "InstructionConverter.hpp"
#include "VirtualMemoryInfo.hpp"
#include "VirtualMemoryMapping.hpp"


using namespace std;
using namespace ROOP;


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

    printf("Setting CWD to the parent directory of the location of this binary...\n");
    setCWDToExecutableLocation();

    currentWorkingDirectory = std::filesystem::current_path();
    pv(currentWorkingDirectory); pn;
}

void testVirtualMemoryMapping(int targetPid) {
    pv(targetPid); pn; pn;

    const VirtualMemoryMapping vmm(targetPid);
    printf("Segment mapping:\n");
    vmm.printMapping();
}

void testPrintCodeSegmentsOfLoadedELFs(int targetPid) {
    pv(targetPid); pn; pn;

    std::set<std::string> loadedELFs;
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
    for (const std::string& elfPath : loadedELFs) {
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

void testVirtualMemoryExecutableBytes(int targetPid) {
    pv(targetPid); pn; pn;

    VirtualMemoryInfo vmBytes(targetPid);
    const std::vector<VirtualMemoryExecutableSegment>& executableSegments = vmBytes.getExecutableSegments();

    printf("Executable Virtual Memory ranges (plus a few bytes from the start of the segment):\n");
    for (const auto& execSegm : executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        unsigned long long start = execSegm.startVirtualAddress;
        unsigned long long end = execSegm.endVirtualAddress;
        unsigned long long actualEnd = start + (unsigned long long)execSegm.executableBytes.size();
        printf("0x%llx-0x%llx (real: 0x%llx-0x%llx; sz: %7llu): ",
               start, end, start, actualEnd, (unsigned long long)execSegm.executableBytes.size());

        size_t bytesToPrint = std::min((size_t)20, execSegm.executableBytes.size());
        for (size_t i = 0; i < bytesToPrint; ++i) {
            printf("%02hhx ", execSegm.executableBytes[i]);
        }
        printf("...\n");
    }
    printf("\n");

    if (executableSegments.size() != 0) {
        const auto& firstExecSegm = executableSegments[0];
        unsigned long long firstSegmStart = firstExecSegm.startVirtualAddress;
        size_t bytesToPrint = std::min((size_t)20, firstExecSegm.executableBytes.size());

        printf("Testing VirtualMemoryInfo::getByteAtVAAddress():\n");
        for (unsigned long long addr = firstSegmStart; addr < firstSegmStart + bytesToPrint; ++addr) {
            ROOP::byte b = vmBytes.getByteAtVAAddress(addr);
            printf("virtual_memory[0x%llx] = %02hhx\n", addr, b);
        }
    }
}

int getPidOfExecutable(string executableName) {
    string tempFile = "pidVulnerable.txt";
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
        exiterror("Failed reading the temp file with the pid...");
    }

    return pid;
}

void testGetExecutableBytesInteractive(string targetExecutable) {
    pv(targetExecutable); pn;

    // You need to start the target executable (under GDB) before running this.
    // And, while both are running, compare the output of this with the output of GDB:
    // $> gdb ./vulnerable.exe
    // (gdb) break main
    // (gdb) start
    // (gdb) x/20bx main
    // (gdb) x/20bx printf
    // ...
    // (gdb) kill
    // They should show the same bytes in memory for virtual addresses of executable(!) segments.

    int targetPid = getPidOfExecutable(targetExecutable);
    pv(targetPid); pn;

    // Print the Virtual Memory ranges of executable bytes in the target process.
    testVirtualMemoryMapping(targetPid); pn;
    testVirtualMemoryExecutableBytes(targetPid); pn;

    VirtualMemoryInfo vmBytes(targetPid);

    printf("Interactive virtual memory inspector...\n");
    while (true) {
        long long addr;
        printf("Please input a virtual memory address (or 0 to exit): ");
        int numMatched = scanf("%lli", &addr);
        if (numMatched != 1) {
            printf("Bad input...\n");
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

        for (unsigned long long cAddr = addr; cAddr < (unsigned long long)addr + 20; ++cAddr) {
            if (!vmBytes.isValidVAAddressInExecutableSegment(cAddr)) {
                break;
            }

            ROOP::byte b = vmBytes.getByteAtVAAddress(cAddr);
            printf("virtual_memory[0x%llx] = 0x%02hhx\n", cAddr, b);
        }
    }
}

void testKeystoneFrameworkIntegration() {
    // Using AT&T syntax for the instructions below.
    ROOP::AssemblySyntax syntax = ROOP::AssemblySyntax::ATT;

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
    for (const string& insSeq : instructionSequences) {
        auto result = ic.convertInstructionSequenceToBytes(insSeq, syntax);
        const byteSequence& byteSeq = result.first;
        unsigned numDecodedInstructions = result.second;

        printf("Instructions: %s\n", insSeq.c_str());
        printf("Decoded %u instructions into %u bytes: ", numDecodedInstructions, (unsigned)byteSeq.size());
        for (const ROOP::byte& b : byteSeq) {
            printf("%02hhX ", (unsigned char)b);
        }
        printf("\n\n");
    }
}

void testCapstoneFrameworkIntegrationBadBytes() {
    byteSequence bytes = {
        // "endbr64" instruction:
        (ROOP::byte)'\xF3',
        (ROOP::byte)'\x0F',
        (ROOP::byte)'\x1E',
        (ROOP::byte)'\xFA',

        // junk:
        (ROOP::byte)'\xFF',
        (ROOP::byte)'\xFF',
    };

    // Disassemble these bytes into assembly instructions as strings;
    InstructionConverter ic;
    auto p = ic.convertInstructionSequenceToString(bytes, ROOP::AssemblySyntax::Intel);
    vector<string> instructions = p.first;

    printf("Number of input bytes: %u\n", (unsigned)bytes.size());
    printf("Number of disassembled bytes: %u\n", (unsigned)p.second);

    printf("Disassembled instructions:\n");
    for (size_t i = 0; i < instructions.size(); ++i) {
        printf("instr[%i] = %s\n", (int)i, instructions[i].c_str());
    }
}

void testKeystoneCapstoneFrameworkIntegration() {
    // Using AT&T syntax for the instructions below.
    ROOP::AssemblySyntax syntax = ROOP::AssemblySyntax::ATT;

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

    InstructionConverter ic;
    for (const string& originalInsSeq : instructionSequences) {
        printf("Original instructions: %s\n", originalInsSeq.c_str());


        // Decode the original instruction sequence (string) into bytes;
        auto originalResult = ic.convertInstructionSequenceToBytes(originalInsSeq, syntax);
        const byteSequence& originalByteSeq = originalResult.first;
        unsigned originalNumDecodedInstructions = originalResult.second;

        printf("Decoded %u instructions into %u bytes: ", originalNumDecodedInstructions, (unsigned)originalByteSeq.size());
        for (const ROOP::byte& b : originalByteSeq) {
            printf("%02hhX ", (unsigned char)b);
        }
        printf("\n");


        // Encode these bytes back into instructions as strings;
        auto p = ic.convertInstructionSequenceToString(originalByteSeq, syntax);
        vector<string> newInstructions = p.first;
        printf("Re-encoded instructions:\n");
        for (size_t i = 0; i < newInstructions.size(); ++i) {
            printf("    instr[%i] = %s\n", (int)i, newInstructions[i].c_str());
        }


        // Decode the new instruction string back into bytes;
        std::string newInstructionSequenceAsm = "";
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
        for (const ROOP::byte& b : newByteSeq) {
            printf("%02hhX ", (unsigned char)b);
        }
        printf("\n\n");
    }
}

void testInstructionNormalization() {
    InstructionConverter ic;

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
        const vector<string>& normalizedInstructions = ic.normalizeInstructionAsm(insAsm, ROOP::AssemblySyntax::Intel);
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
        const vector<string>& normalizedInstructions = ic.normalizeInstructionAsm(insAsm, ROOP::AssemblySyntax::ATT);
        const string& normalizedInsAsm = ic.concatenateInstructionsAsm(normalizedInstructions);
        printf("insAsm = %s\n", insAsm.c_str());
        printf("normalizedInsAsm = %s\n", normalizedInsAsm.c_str());
    }
}

void testFindingInstructionSequenceInMemory(string targetExecutable) {
    // You need to start the target executable (under GDB) before running this.
    // And then compare the output of this function with the output of GDB:
    // $> gdb ./vulnerable.exe
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

    VirtualMemoryInfo vmInfo(targetPid);
    printf("Finished initializing vmInfo object!\n\n");

    // These are some sample instruction sequences found in libc.so.6
    // Note: Using Intel syntax here.
    ROOP::AssemblySyntax syntax = ROOP::AssemblySyntax::Intel;
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

    InstructionConverter ic;

    printf("======= Searching for instruction sequences in virtual memory... =======\n");
    for (const string& insSeq : instructionSequences) {
        printf("Instruction sequence: %s\n", insSeq.c_str());

        auto normalizedArray = ic.normalizeInstructionAsm(insSeq, AssemblySyntax::Intel);
        auto normalizedString = ic.concatenateInstructionsAsm(normalizedArray);
        printf("Normalized instruction sequence: %s\n", normalizedString.c_str());

        vector<unsigned long long> matchedAddresses = vmInfo.matchInstructionSequenceInVirtualMemory(insSeq, syntax);
        if (matchedAddresses.size() != 0) {
            for (unsigned long long addr : matchedAddresses) {
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

    VirtualMemoryInfo vmInfo(targetPid);
    printf("Finished initializing vmInfo object!\n\n");

    InstructionConverter ic;

    printf("Found instruction sequences:\n");
    auto instrSeqs = vmInfo.getInstructionSequences();
    for (const auto& p : instrSeqs) {
        unsigned long long addr = p.first;
        string fullSequence = ic.concatenateInstructionsAsm(p.second);
        printf("0x%10llx: %s\n", addr, fullSequence.c_str());
    }
}


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    printProcessInformation(argc, argv); pn;
    normalizeCWD(); pn;

    // testVirtualMemoryMapping(getpid()); pn;
    // testPrintCodeSegmentsOfLoadedELFs(getpid()); pn;
    // testVirtualMemoryExecutableBytes(getpid()); pn;
    // testGetExecutableBytesInteractive("vulnerable.exe"); pn;
    // testKeystoneFrameworkIntegration(); pn;
    // testCapstoneFrameworkIntegrationBadBytes(); pn;
    // testKeystoneCapstoneFrameworkIntegration(); pn;
    // testInstructionNormalization(); pn;
    // testFindingInstructionSequenceInMemory("vulnerable.exe"); pn;
    printVMInstructionSequences("vulnerable.exe"); pn;

    return 0;
}
