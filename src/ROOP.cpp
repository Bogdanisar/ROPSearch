#include <assert.h>
#include <iostream>
#include <set>
#include <unistd.h>

#include "common/utils.hpp"
#include "VirtualMemoryMapping.hpp"
#include "ELFParser.hpp"


using namespace std;
using namespace ROOP;


void testVirtualMemoryMapping(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    const VirtualMemoryMapping vmm(getpid());
    vmm.printSegments();
}

void testPrintCodeSegmentsOfLoadedELFs(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    std::set<std::string> loadedELFs;

    const VirtualMemoryMapping vmm(getpid());
    for (const VirtualMemorySegment& segm : vmm.getSegments()) {
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
        for (const Elf64_Phdr& hdr : codeSegmentHeaders) {
            bool isReadable = ((hdr.p_flags & PF_R) != 0);
            bool isWritable = ((hdr.p_flags & PF_W) != 0);
            bool isExecutable = ((hdr.p_flags & PF_X) != 0);

            printf("%#018llx %#018llx %#018llx %#018llx %#018llx %c%c%c    %#018llx",
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


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    // testVirtualMemoryMapping(argc, argv);
    testPrintCodeSegmentsOfLoadedELFs(argc, argv);

    return 0;
}
