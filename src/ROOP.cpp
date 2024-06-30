#include <iostream>
#include <unistd.h>

#include "utils.hpp"
#include "VirtualMemoryMapping.hpp"
#include "ELFParser.hpp"


using namespace std;
using namespace ROOP;


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);

    cout << "Hello, world!\n";

    const VirtualMemoryMapping vmm(getpid());
    vmm.printSegments();

    for (const VirtualMemorySegment& segm : vmm.getSegments()) {
        pv(segm.path); pn;
        if (ELFParser::elfPathIsAcceptable(segm.path)) {
            ELFParser(segm.path);
        }
    }

    return 0;
}
