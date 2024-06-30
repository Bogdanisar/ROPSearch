#ifndef VIRTUAL_MEMORY_MAPPING_H
#define VIRTUAL_MEMORY_MAPPING_H

#include <string>
#include <vector>


namespace ROOP {

    struct VirtualMemorySegment {
        unsigned long long startAddress;
        unsigned long long endAddress;
        char rights[5];
        unsigned int rightsMask;
        unsigned long long offset;
        unsigned long long deviceMajor, deviceMinor;
        unsigned long long inodeNumber;
        std::string path;

        enum class SegmentRights {
            READ = 1<<0,
            WRITE = 1<<1,
            EXECUTE = 1<<2,
            PRIVATE = 1<<3
        };

        void printSegment();
    };

    class VirtualMemoryMapping {
        std::vector<VirtualMemorySegment> segments;

        public:
        VirtualMemoryMapping(int processPid);
        void printSegments();
    };

}


#endif // VIRTUAL_MEMORY_MAPPING_H
