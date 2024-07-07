#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

#include "common/utils.hpp"
#include "ELFParser.hpp"
#include "VirtualMemoryExecutableBytes.hpp"
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

    VirtualMemoryExecutableBytes vmBytes(targetPid);
    const std::vector<VirtualMemoryExecutableSegment>& executableSegments = vmBytes.getExecutableSegments();

    printf("Executable Virtual Memory ranges (plus a few bytes from the start of the segment):\n");
    for (const auto& execSegm : executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        unsigned long long start = execSegm.startVirtualAddress;
        unsigned long long end = execSegm.endVirtualAddress;
        unsigned long long actualEnd = start + (unsigned long long)execSegm.executableBytes.size();
        printf("0x%llx-0x%llx (actual: 0x%llx-0x%llx): ", start, end, start, actualEnd);

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

        printf("Testing VirtualMemoryExecutableBytes::getByteAtVAAddress():\n");
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

    VirtualMemoryExecutableBytes vmBytes(targetPid);

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


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    printProcessInformation(argc, argv); pn;
    normalizeCWD(); pn;

    // testVirtualMemoryMapping(getpid()); pn;
    // testPrintCodeSegmentsOfLoadedELFs(getpid()); pn;
    // testVirtualMemoryExecutableBytes(getpid()); pn;
    testGetExecutableBytesInteractive("vulnerable.exe"); pn;

    return 0;
}
