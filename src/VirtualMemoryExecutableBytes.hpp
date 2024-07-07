#ifndef VIRTUAL_MEMORY_EXECUTABLE_BYTES_H
#define VIRTUAL_MEMORY_EXECUTABLE_BYTES_H

#include <string>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "VirtualMemoryMapping.hpp"


namespace ROOP {

    struct VirtualMemoryExecutableSegment {
        // The end address might be larger than start + bytes.size(),
        // because of needing to be a multiple of the page size.
        unsigned long long startVirtualAddress;
        unsigned long long endVirtualAddress;
        std::vector<byte> executableBytes;
    };

    class VirtualMemoryExecutableBytes {
        VirtualMemoryMapping vaSegmMapping;
        std::vector<VirtualMemoryExecutableSegment> executableSegments;

        public:
        VirtualMemoryExecutableBytes(int processPid);

        const VirtualMemoryMapping& getVASegmMapping() const;
        const std::vector<VirtualMemoryExecutableSegment>& getExecutableSegments() const;

        bool isValidVAAddressInExecutableSegment(unsigned long long vaAddress) const;
        byte getByteAtVAAddress(unsigned long long vaAddress) const;
    };

}


#endif // VIRTUAL_MEMORY_EXECUTABLE_BYTES_H
