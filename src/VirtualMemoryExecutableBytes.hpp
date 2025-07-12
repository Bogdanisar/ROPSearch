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


namespace ROP {

    struct VirtualMemoryExecutableSegment {
        // The end address might be larger than start + bytes.size(),
        // because of needing to be a multiple of the page size.
        addressType startVirtualAddress;
        addressType endVirtualAddress;
        byteSequence executableBytes;
        std::string sourceName;
    };

    class VirtualMemoryExecutableBytes {
        BitSizeClass processArchSize;
        std::vector<VirtualMemoryExecutableSegment> executableSegments;

        void buildExecutableSegments(int processPid);
        void buildExecutableSegments(const std::vector<std::string> execPaths,
                                     const std::vector<addressType> baseAddresses);

        public:
        /**
         * Get executable bytes by reading the "/proc/PID/maps" file
         * and then loading executable segments from each ELF file according to the mapping.
         */
        VirtualMemoryExecutableBytes(int processPid);

        /**
         * Load all executable segments from each given executable path.
         * @param execPaths Paths to executable files.
         * @param baseAddresses Values that will be used, in order, as a base address for each executable file.
         *                      If this array is empty or has fewer addresses than the total number of files,
         *                      then the value 0 will be used as a default.
         */
        VirtualMemoryExecutableBytes(const std::vector<std::string> execPaths,
                                     const std::vector<addressType> baseAddresses);

        const BitSizeClass& getProcessArchSize() const;
        const std::vector<VirtualMemoryExecutableSegment>& getExecutableSegments() const;

        bool isValidVirtualAddressInExecutableSegment(addressType vAddress) const;
        byte getByteAtVirtualAddress(addressType vAddress) const;

        // Return a vector of addresses where the bytes are found in virtual memory.
        std::vector<addressType> matchBytesInVirtualMemory(byteSequence bytes);
    };

}


#endif // VIRTUAL_MEMORY_EXECUTABLE_BYTES_H
