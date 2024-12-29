#include "VirtualMemoryExecutableBytes.hpp"

#include <algorithm>

#include "ELFParser.hpp"


void ROP::VirtualMemoryExecutableBytes::buildExecutableSegments() {
    // This is used as an optimization in case there are multiple executable segments for the same ELF path.
    // (Otherwise, we would need to create an ELFParser multiple times for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    const std::vector<VirtualMemorySegmentMapping>& allSegmentMaps = this->vmSegmMapping.getSegmentMaps();
    for (const VirtualMemorySegmentMapping& segmentMap : allSegmentMaps) {
        if (!ELFParser::elfPathIsAcceptable(segmentMap.path)) {
            continue;
        }

        bool isExecutable = (segmentMap.rightsMask & (unsigned int)ROP::VirtualMemorySegmentMapping::SegmentRights::EXECUTE);
        if (!isExecutable) {
            continue;
        }

        if (elfPathToELFParser.count(segmentMap.path) == 0) {
            elfPathToELFParser[segmentMap.path] = ELFParser(segmentMap.path);
        }

        ELFParser& elfParser = elfPathToELFParser[segmentMap.path];
        const std::vector<Elf64_Phdr>& elfCodeSegmentHdrs = elfParser.getCodeSegmentHeaders();
        const std::vector<byteSequence>& elfCodeSegmentBytes = elfParser.getCodeSegmentBytes();
        for (size_t i = 0; i < elfCodeSegmentHdrs.size(); ++i) {
            const Elf64_Phdr& codeSegmHdr = elfCodeSegmentHdrs[i];
            const byteSequence& codeSegmBytes = elfCodeSegmentBytes[i];

            if ((Elf64_Off)segmentMap.offset != codeSegmHdr.p_offset) {
                continue;
            }

            VirtualMemoryExecutableSegment execSegm;
            execSegm.startVirtualAddress = segmentMap.startAddress;
            execSegm.endVirtualAddress = segmentMap.endAddress;
            execSegm.executableBytes = codeSegmBytes;
            this->executableSegments.push_back(execSegm);
        }
    }

    auto comparator = [](const VirtualMemoryExecutableSegment& a, const VirtualMemoryExecutableSegment& b){
        return a.startVirtualAddress < b.startVirtualAddress;
    };

    // They come sorted by default (from /proc/PID/maps), but just in case.
    std::sort(this->executableSegments.begin(), this->executableSegments.end(), comparator);
}

ROP::VirtualMemoryExecutableBytes::VirtualMemoryExecutableBytes(int processPid)
: vmSegmMapping(processPid) {
    this->buildExecutableSegments();
}


const ROP::VirtualMemoryMapping& ROP::VirtualMemoryExecutableBytes::getVMSegmMapping() const {
    return this->vmSegmMapping;
}

const std::vector<ROP::VirtualMemoryExecutableSegment>& ROP::VirtualMemoryExecutableBytes::getExecutableSegments() const {
    return this->executableSegments;
}

bool ROP::VirtualMemoryExecutableBytes::isValidVirtualAddressInExecutableSegment(unsigned long long vAddress) const {
    for (const auto& execSegm : this->executableSegments) {
        if (execSegm.startVirtualAddress <= vAddress && vAddress < execSegm.endVirtualAddress) {
            return true;
        }
    }

    return false;
}

ROP::byte ROP::VirtualMemoryExecutableBytes::getByteAtVirtualAddress(unsigned long long vAddress) const {
    for (const auto& execSegm : this->executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        unsigned long long start = execSegm.startVirtualAddress;
        unsigned long long end = execSegm.endVirtualAddress;
        unsigned long long actualEnd = start + (unsigned long long)execSegm.executableBytes.size();

        if (start <= vAddress && vAddress < actualEnd) {
            return execSegm.executableBytes[vAddress - start];
        }
        else if (start <= vAddress && vAddress < end) {
            return (byte)0;
        }
    }

    LogWarn("Bad query in Virtual Memory! Can't find address: %llu (0x%llx)\n", vAddress, vAddress);
    return (byte)0;
}

std::vector<unsigned long long>
ROP::VirtualMemoryExecutableBytes::matchBytesInVirtualMemory(ROP::byteSequence bytes) {
    assertMessage(bytes.size() != 0, "Got empty bytes sequence...");

    std::vector<unsigned long long> matchedVirtualAddresses;

    for (const VirtualMemoryExecutableSegment& execSegm : this->executableSegments) {
        const byteSequence& segmentBytes = execSegm.executableBytes;
        int sizeCodeBytes = (int)segmentBytes.size();
        int sizeTargetBytes = (int)bytes.size();

        for (int low = 0, high = sizeTargetBytes - 1; high < sizeCodeBytes; ++low, ++high) {
            bool match = true;
            for (int idx = 0; idx < sizeTargetBytes; ++idx) {
                if (bytes[idx] != segmentBytes[low + idx]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                matchedVirtualAddresses.push_back(execSegm.startVirtualAddress + low);
            }
        }
    }

    return matchedVirtualAddresses;
}
