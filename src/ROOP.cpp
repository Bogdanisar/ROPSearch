#include <iostream>
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

void testELFParser(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    const VirtualMemoryMapping vmm(getpid());
    for (const VirtualMemorySegment& segm : vmm.getSegments()) {
        if (!ELFParser::elfPathIsAcceptable(segm.path)) {
            printf("Not valid segment of ELF file: %s\n", segm.path.c_str());
        }
    }
    printf("\n");

    for (const VirtualMemorySegment& segm : vmm.getSegments()) {
        if (ELFParser::elfPathIsAcceptable(segm.path)) {
            ELFParser parser(segm.path);
            auto fileHeader = parser.getFileHeader();

            printf("Segment of ELF file: %s\n", segm.path.c_str());
            printf("e_ident: ");
            for (int i = 0; i < EI_NIDENT; ++i) {
                printf("%hhX ", fileHeader.e_ident[i]);
            }

            printf("(");
            for (int i = 0; i < EI_NIDENT; ++i) {
                char c = isprint(fileHeader.e_ident[i]) ? fileHeader.e_ident[i] : '.';
                printf("%c", c);
            }
            printf(")");

            printf("\n\n");
        }
    }
}


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    // testVirtualMemoryMapping(argc, argv);
    testELFParser(argc, argv);

    return 0;
}
