#ifndef VIRTUAL_MEMORY_BYTES_H
#define VIRTUAL_MEMORY_BYTES_H

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"


namespace ROP {

    struct VirtualMemorySegmentBytes {
        // The end address might be larger than start + bytes.size(),
        // because of needing to be a multiple of the page size.
        addressType startVirtualAddress;
        addressType endVirtualAddress;
        byteSequence bytes;
        std::string sourceName;
    };

    class VirtualMemoryBytes {
        BitSizeClass processArchSize;
        std::vector<VirtualMemorySegmentBytes> readSegments;
        std::vector<VirtualMemorySegmentBytes> executableSegments;

        void buildVirtualMemorySegments(int processPid);
        void buildVirtualMemorySegments(const std::vector<std::string> execPaths,
                                        const std::vector<addressType> baseAddresses);
        void sortSegments();

        public:
        /**
         * Get loadable segment bytes by reading the "/proc/PID/maps" file
         * and then loading segments from each ELF file according to the mapping.
         */
        VirtualMemoryBytes(int processPid);

        /**
         * Get loadable segments from each given executable path.
         * @param execPaths Paths to executable files.
         * @param baseAddresses Values that will be used, in order, as a base address for each executable file.
         *                      If this array is empty or has fewer addresses than the total number of files,
         *                      then the value 0 will be used as a default.
         */
        VirtualMemoryBytes(const std::vector<std::string> execPaths,
                           const std::vector<addressType> baseAddresses);

        const BitSizeClass& getProcessArchSize() const;
        const std::vector<VirtualMemorySegmentBytes>& getReadSegments() const;
        const std::vector<VirtualMemorySegmentBytes>& getExecutableSegments() const;

        bool isValidVirtualAddress(addressType vAddress) const;
        byte getByteAtVirtualAddress(addressType vAddress) const;

        // Return a vector of addresses where the bytes are found in virtual memory.
        std::vector<addressType> matchBytesInVirtualMemory(const byteSequence& targetBytes) const;
        // Return a vector of addresses where the string is found in virtual memory.
        std::vector<addressType> matchStringInVirtualMemory(const char * const targetString) const;
    };

}


#endif // VIRTUAL_MEMORY_BYTES_H
