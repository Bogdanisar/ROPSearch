#ifndef VIRTUAL_MEMORY_MAPPING_H
#define VIRTUAL_MEMORY_MAPPING_H

#include <string>
#include <vector>


namespace ROP {

    struct VirtualMemorySegmentMapping {
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

        // Will print it like in /proc/PID/maps
        void printSegment() const;
    };

    class VirtualMemoryMapping {
        std::vector<VirtualMemorySegmentMapping> segmentMaps;

        public:
        VirtualMemoryMapping(int processPid);
        const std::vector<VirtualMemorySegmentMapping>& getSegmentMaps() const;

        // Will print it like in /proc/PID/maps (all segments)
        void printMapping() const;
    };

}


#endif // VIRTUAL_MEMORY_MAPPING_H
