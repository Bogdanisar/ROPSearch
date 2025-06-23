#include "VirtualMemoryExecutableBytes.hpp"

#include <algorithm>
#include <filesystem>

#include "ELFParser.hpp"
#include "VirtualMemoryMapping.hpp"


void ROP::VirtualMemoryExecutableBytes::buildExecutableSegments(int processPid) {
    const VirtualMemoryMapping& vmSegmMapping(processPid);

    // This is used as an optimization in case there are multiple executable segments for the same ELF path.
    // (Otherwise, we would need to create an ELFParser multiple times for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    // We'll use this to ensure that all found executables are 32bit or 64bit.
    std::set<BitSizeClass> foundArchSizes;

    const std::vector<VirtualMemorySegmentMapping>& allSegmentMaps = vmSegmMapping.getSegmentMaps();
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

        // Remember the executable architecture size.
        auto archSize = elfParser.getFileBitType();
        foundArchSizes.insert(archSize);

        // Iterate through the segments to find the ones relevant for this process.
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
            execSegm.sourceName = std::filesystem::path(segmentMap.path).filename();
            this->executableSegments.push_back(execSegm);
        }
    }

    // Remember the architecture size.
    if (foundArchSizes.size() != 1) {
        exitError("Found %u different architecture sizes (32bit/64bit) when loading the bytes of process with pid %u",
                  (unsigned)foundArchSizes.size(), (unsigned)processPid);
    }
    this->processArchSize = *foundArchSizes.begin();

    // Sort the found executable segments.
    // They seem to come sorted by default (from /proc/PID/maps), but just in case.
    auto comparator = [](const VirtualMemoryExecutableSegment& a, const VirtualMemoryExecutableSegment& b){
        return a.startVirtualAddress < b.startVirtualAddress;
    };
    std::sort(this->executableSegments.begin(), this->executableSegments.end(), comparator);
}

void ROP::VirtualMemoryExecutableBytes::buildExecutableSegments(const std::vector<std::string> execPaths,
                                                                const std::vector<addressType> baseAddresses) {
    // This is used as an optimization in case we have the same ELF path multiple times.
    // (Otherwise, we would need to create more than one ELFParser for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    // We'll use this to ensure that all executables are 32bit or 64bit.
    std::set<BitSizeClass> foundArchSizes;

    unsigned addrIndex = 0;
    for (const std::string& path : execPaths) {
        assertMessage(ELFParser::elfPathIsAcceptable(path), "Bad path: \"%s\"", path.c_str());

        if (elfPathToELFParser.count(path) == 0) {
            elfPathToELFParser[path] = ELFParser(path);
        }

        ELFParser& elfParser = elfPathToELFParser[path];

        // Remember the executable architecture size.
        auto archSize = elfParser.getFileBitType();
        foundArchSizes.insert(archSize);

        // Iterate through all the segments to store the executable ones.
        const std::vector<Elf64_Phdr>& elfCodeSegmentHdrs = elfParser.getCodeSegmentHeaders();
        const std::vector<byteSequence>& elfCodeSegmentBytes = elfParser.getCodeSegmentBytes();
        for (size_t i = 0; i < elfCodeSegmentHdrs.size(); ++i) {
            const Elf64_Phdr& codeSegmHdr = elfCodeSegmentHdrs[i];
            const byteSequence& codeSegmBytes = elfCodeSegmentBytes[i];

            VirtualMemoryExecutableSegment execSegm;

            if (addrIndex < baseAddresses.size()) {
                execSegm.startVirtualAddress = baseAddresses[addrIndex++];
            }
            else {
                execSegm.startVirtualAddress = codeSegmHdr.p_vaddr;
            }

            // Maybe use `execSegm.startVirtualAddress + codeSegmHdr.p_memsz` ?
            execSegm.endVirtualAddress = execSegm.startVirtualAddress + codeSegmBytes.size();
            execSegm.executableBytes = codeSegmBytes;

            this->executableSegments.push_back(execSegm);
        }
    }

    // Remember the architecture size.
    if (foundArchSizes.size() != 1) {
        exitError("Found %u different architecture sizes (32bit/64bit) when loading the given executables...",
                  (unsigned)foundArchSizes.size());
    }
    this->processArchSize = *foundArchSizes.begin();

    // Sort the found executable segments.
    auto comparator = [](const VirtualMemoryExecutableSegment& a, const VirtualMemoryExecutableSegment& b){
        return a.startVirtualAddress < b.startVirtualAddress;
    };
    std::sort(this->executableSegments.begin(), this->executableSegments.end(), comparator);
}

ROP::VirtualMemoryExecutableBytes::VirtualMemoryExecutableBytes(int processPid) {
    this->buildExecutableSegments(processPid);
}

ROP::VirtualMemoryExecutableBytes::VirtualMemoryExecutableBytes(const std::vector<std::string> execPaths,
                                                                const std::vector<addressType> baseAddresses) {
    this->buildExecutableSegments(execPaths, baseAddresses);
}


const ROP::BitSizeClass& ROP::VirtualMemoryExecutableBytes::getProcessArchSize() const {
    return this->processArchSize;
}

const std::vector<ROP::VirtualMemoryExecutableSegment>& ROP::VirtualMemoryExecutableBytes::getExecutableSegments() const {
    return this->executableSegments;
}

bool ROP::VirtualMemoryExecutableBytes::isValidVirtualAddressInExecutableSegment(addressType vAddress) const {
    for (const auto& execSegm : this->executableSegments) {
        if (execSegm.startVirtualAddress <= vAddress && vAddress < execSegm.endVirtualAddress) {
            return true;
        }
    }

    return false;
}

ROP::byte ROP::VirtualMemoryExecutableBytes::getByteAtVirtualAddress(addressType vAddress) const {
    for (const auto& execSegm : this->executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        addressType start = execSegm.startVirtualAddress;
        addressType end = execSegm.endVirtualAddress;
        addressType actualEnd = start + (unsigned long long)execSegm.executableBytes.size();

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

std::vector<ROP::addressType>
ROP::VirtualMemoryExecutableBytes::matchBytesInVirtualMemory(ROP::byteSequence bytes) {
    assertMessage(bytes.size() != 0, "Got empty bytes sequence...");

    std::vector<addressType> matchedVirtualAddresses;

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
