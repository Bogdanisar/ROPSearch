#ifndef VIRTUAL_MEMORY_EXECUTABLE_BYTES_H
#define VIRTUAL_MEMORY_EXECUTABLE_BYTES_H

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "VirtualMemoryMapping.hpp"


namespace ROP {

    struct VirtualMemoryExecutableSegment {
        // The end address might be larger than start + bytes.size(),
        // because of needing to be a multiple of the page size.
        unsigned long long startVirtualAddress;
        unsigned long long endVirtualAddress;
        byteSequence executableBytes;
    };

    class VirtualMemoryExecutableBytes {
        VirtualMemoryMapping vmSegmMapping;
        std::vector<VirtualMemoryExecutableSegment> executableSegments;

        void buildExecutableSegments();

        public:
        VirtualMemoryExecutableBytes(int processPid);

        const VirtualMemoryMapping& getVMSegmMapping() const;
        const std::vector<VirtualMemoryExecutableSegment>& getExecutableSegments() const;

        bool isValidVirtualAddressInExecutableSegment(unsigned long long vAddress) const;
        byte getByteAtVirtualAddress(unsigned long long vAddress) const;

        // Return a vector of addresses where the bytes are found in virtual memory.
        std::vector<unsigned long long> matchBytesInVirtualMemory(byteSequence bytes);
    };

}


#endif // VIRTUAL_MEMORY_EXECUTABLE_BYTES_H
