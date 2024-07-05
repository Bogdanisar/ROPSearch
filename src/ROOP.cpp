#include <assert.h>
#include <iostream>
#include <set>
#include <unistd.h>

#include "common/utils.hpp"
#include "ELFParser.hpp"
#include "VirtualMemoryExecutableBytes.hpp"
#include "VirtualMemoryMapping.hpp"


using namespace std;
using namespace ROOP;


void testVirtualMemoryMapping(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    const VirtualMemoryMapping vmm(getpid());
    vmm.printMapping();
}

void testPrintCodeSegmentsOfLoadedELFs(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    std::set<std::string> loadedELFs;

    const VirtualMemoryMapping vmm(getpid());
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

void testVirtualMemoryExecutableBytes(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    VirtualMemoryExecutableBytes vmBytes(getpid());
    const std::vector<VirtualMemoryExecutableSegment>& executableSegments = vmBytes.getExecutableSegments();

    for (const auto& execSegm : executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        unsigned long long start = execSegm.startVirtualAddress;
        unsigned long long end = execSegm.endVirtualAddress;
        unsigned long long actualEnd = start + (unsigned long long)execSegm.executableBytes.size();
        printf("%llx-%llx (actual: %llx-%llx): ", start, end, start, actualEnd);

        size_t bytesToPrint = std::min((size_t)10, execSegm.executableBytes.size());
        for (size_t i = 0; i < bytesToPrint; ++i) {
            printf("%02hhx ", execSegm.executableBytes[i]);
        }
        printf("...\n");
    }

    // TODO: Test getByteAtVAAddress
}


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    long pageSize = sysconf(_SC_PAGESIZE);
    pv(pageSize); pn;
    pv(getpid()); pn; pn;

    testVirtualMemoryMapping(argc, argv); pn;
    // testPrintCodeSegmentsOfLoadedELFs(argc, argv); pn;
    testVirtualMemoryExecutableBytes(argc, argv); pn;

    return 0;
}
