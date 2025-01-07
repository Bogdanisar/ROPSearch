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
        std::vector<VirtualMemoryExecutableSegment> executableSegments;

        void buildExecutableSegments(int processPid);
        void buildExecutableSegments(const std::vector<std::string> execPaths,
                                     const std::vector<unsigned long long> baseAddresses);

        public:
        /**
         * Get executable bytes by reading the "/proc/PID/maps" file
         * and then loading executable segments from each ELF file according to the mapping.
         */
        VirtualMemoryExecutableBytes(int processPid);

        /**
         * Load all executable segments from each given executable path.
         * @param execPaths Paths to executable files.
         * @param baseAddresses Values that will be used, in order, as a base address
         *                      for each executable segment that we find in the given executable files.
         *                      If this array is empty or has fewer addresses than the total number of segments,
         *                      the Elf64_Phdr.p_vaddr value found in the ELF file will be used instead.
         */
        VirtualMemoryExecutableBytes(const std::vector<std::string> execPaths,
                                     const std::vector<unsigned long long> baseAddresses);

        const std::vector<VirtualMemoryExecutableSegment>& getExecutableSegments() const;

        bool isValidVirtualAddressInExecutableSegment(unsigned long long vAddress) const;
        byte getByteAtVirtualAddress(unsigned long long vAddress) const;

        // Return a vector of addresses where the bytes are found in virtual memory.
        std::vector<unsigned long long> matchBytesInVirtualMemory(byteSequence bytes);
    };

}


#endif // VIRTUAL_MEMORY_EXECUTABLE_BYTES_H
