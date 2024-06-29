#include <iostream>
#include <unistd.h>

#include "VirtualMemoryMapping.hpp"


using namespace std;
using namespace ROOP;


int main(int argc, char* argv[]) {
    cout << "Hello, world!\n";

    VirtualMemoryMapping vmm(getpid());
    vmm.printSegments();

    return 0;
}
