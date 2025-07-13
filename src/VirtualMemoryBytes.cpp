#include "VirtualMemoryBytes.hpp"

#include <algorithm>
#include <filesystem>

#include "ELFParser.hpp"
#include "VirtualMemoryMapping.hpp"


void ROP::VirtualMemoryBytes::buildVirtualMemorySegments(int processPid) {
    const VirtualMemoryMapping& vmSegmMapping(processPid);

    // This is used as an optimization in case there are multiple segments for the same ELF path.
    // (Otherwise, we would need to create an ELFParser multiple times for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    // We'll use this to ensure that all found executables are 32bit or 64bit.
    std::set<BitSizeClass> foundArchSizes;

    const std::vector<VirtualMemorySegmentMapping>& allSegmentMaps = vmSegmMapping.getSegmentMaps();
    for (const VirtualMemorySegmentMapping& segmentMap : allSegmentMaps) {
        if (!ELFParser::elfPathIsAcceptable(segmentMap.path)) {
            continue;
        }

        bool segmIsReadable = (segmentMap.rightsMask & (unsigned int)ROP::VirtualMemorySegmentMapping::SegmentRights::READ);
        bool segmIsWriteable = (segmentMap.rightsMask & (unsigned int)ROP::VirtualMemorySegmentMapping::SegmentRights::WRITE);
        bool segmIsExecutable = (segmentMap.rightsMask & (unsigned int)ROP::VirtualMemorySegmentMapping::SegmentRights::EXECUTE);
        if (!segmIsReadable) {
            // A non-readable segment can't be useful for us here.
            continue;
        }

        if (elfPathToELFParser.count(segmentMap.path) == 0) {
            elfPathToELFParser[segmentMap.path] = ELFParser(segmentMap.path);
        }

        ELFParser& elfParser = elfPathToELFParser[segmentMap.path];

        // Remember the executable architecture size.
        auto archSize = elfParser.getFileBitType();
        foundArchSizes.insert(archSize);

        // Iterate through the loadable segments to store the ones relevant for this process.
        const std::vector<Elf64_Phdr>& elfSegmentHdrs = elfParser.getSegmentHeaders();
        const std::vector<byteSequence>& elfSegmentBytes = elfParser.getSegmentBytes();
        assert(elfSegmentHdrs.size() == elfSegmentBytes.size());
        for (size_t i = 0; i < elfSegmentHdrs.size(); ++i) {
            const Elf64_Phdr& segmHeader = elfSegmentHdrs[i];
            const byteSequence& segmBytes = elfSegmentBytes[i];

            if ((Elf64_Off)segmentMap.offset != segmHeader.p_offset) {
                continue;
            }

            VirtualMemorySegmentBytes segm;
            segm.startVirtualAddress = segmentMap.startAddress;
            segm.endVirtualAddress = segmentMap.endAddress;
            segm.bytes = segmBytes;
            segm.sourceName = std::filesystem::path(segmentMap.path).filename();

            if (segmIsReadable && !segmIsWriteable) {
                this->readSegments.push_back(segm);
            }
            if (segmIsReadable && segmIsExecutable) {
                this->executableSegments.push_back(segm);
            }
        }
    }

    // Remember the architecture size.
    if (foundArchSizes.size() != 1) {
        exitError("Found %u different architecture sizes (32bit/64bit) when loading the bytes of process with pid %u",
                  (unsigned)foundArchSizes.size(), (unsigned)processPid);
    }
    this->processArchSize = *foundArchSizes.begin();
}

void ROP::VirtualMemoryBytes::buildVirtualMemorySegments(const std::vector<std::string> execPaths,
                                                         const std::vector<addressType> baseAddresses) {
    // This is used as an optimization in case we have the same ELF path multiple times.
    // (Otherwise, we would need to create more than one ELFParser for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    // We'll use this to ensure that all executables are 32bit or 64bit.
    std::set<BitSizeClass> foundArchSizes;

    for (unsigned idx = 0; idx < execPaths.size(); ++idx) {
        const std::string& path = execPaths[idx];
        assertMessage(ELFParser::elfPathIsAcceptable(path), "Bad path: \"%s\"", path.c_str());

        if (elfPathToELFParser.count(path) == 0) {
            elfPathToELFParser[path] = ELFParser(path);
        }

        ELFParser& elfParser = elfPathToELFParser[path];

        // Remember the executable architecture size.
        auto archSize = elfParser.getFileBitType();
        foundArchSizes.insert(archSize);

        // Get the base memory address for this ELF file,
        // at which the loadable segments are loaded.
        addressType baseMemoryAddress = 0;
        if (idx < baseAddresses.size()) {
            baseMemoryAddress = baseAddresses[idx];
        }
        const addressType lowestVAddr = elfParser.getLowestVirtualAddressOfLoadableSegment();

        // Iterate through the loadable segments to store the relevant ones.
        const std::vector<Elf64_Phdr>& elfSegmentHdrs = elfParser.getSegmentHeaders();
        const std::vector<byteSequence>& elfSegmentBytes = elfParser.getSegmentBytes();
        assert(elfSegmentHdrs.size() == elfSegmentBytes.size());
        for (size_t i = 0; i < elfSegmentHdrs.size(); ++i) {
            const Elf64_Phdr& segmHeader = elfSegmentHdrs[i];
            const byteSequence& segmBytes = elfSegmentBytes[i];

            assertMessage(segmHeader.p_vaddr > lowestVAddr,
                          "Invalid ELF format. The first loadable segment should have the smallest .p_vaddr value");

            // Maybe use `segm.endVirtualAddress = segm.startVirtualAddress + segmHeader.p_memsz` ?
            VirtualMemorySegmentBytes segm;
            segm.startVirtualAddress = baseMemoryAddress + (segmHeader.p_vaddr - lowestVAddr);
            segm.endVirtualAddress = segm.startVirtualAddress + segmBytes.size();
            segm.bytes = segmBytes;

            bool segmIsReadable = ((segmHeader.p_flags & PF_R) != 0);
            bool segmIsWritable = ((segmHeader.p_flags & PF_W) != 0);
            bool segmIsExecutable = ((segmHeader.p_flags & PF_X) != 0);
            if (segmIsReadable && !segmIsWritable) {
                this->readSegments.push_back(segm);
            }
            if (segmIsReadable && segmIsExecutable) {
                this->executableSegments.push_back(segm);
            }
        }
    }

    // Remember the architecture size.
    if (foundArchSizes.size() != 1) {
        exitError("Found %u different architecture sizes (32bit/64bit) when loading the given executables...",
                  (unsigned)foundArchSizes.size());
    }
    this->processArchSize = *foundArchSizes.begin();
}

void ROP::VirtualMemoryBytes::sortSegments() {
    // Sort the found segments.
    auto comparator = [](const VirtualMemorySegmentBytes& a, const VirtualMemorySegmentBytes& b){
        return a.startVirtualAddress < b.startVirtualAddress;
    };
    std::sort(this->readSegments.begin(), this->readSegments.end(), comparator);
    std::sort(this->executableSegments.begin(), this->executableSegments.end(), comparator);
}

ROP::VirtualMemoryBytes::VirtualMemoryBytes(int processPid) {
    this->buildVirtualMemorySegments(processPid);

    // They seem to come sorted by default (from /proc/PID/maps), but just in case.
    this->sortSegments();
}

ROP::VirtualMemoryBytes::VirtualMemoryBytes(const std::vector<std::string> execPaths,
                                            const std::vector<addressType> baseAddresses) {
    this->buildVirtualMemorySegments(execPaths, baseAddresses);
    this->sortSegments();
}


const ROP::BitSizeClass& ROP::VirtualMemoryBytes::getProcessArchSize() const {
    return this->processArchSize;
}

const std::vector<ROP::VirtualMemorySegmentBytes>& ROP::VirtualMemoryBytes::getReadSegments() const {
    return this->readSegments;
}

const std::vector<ROP::VirtualMemorySegmentBytes>& ROP::VirtualMemoryBytes::getExecutableSegments() const {
    return this->executableSegments;
}


bool ROP::VirtualMemoryBytes::isValidVirtualAddress(addressType vAddress) const {
    for (const auto& segm : this->readSegments) {
        if (segm.startVirtualAddress <= vAddress && vAddress < segm.endVirtualAddress) {
            return true;
        }
    }

    return false;
}

ROP::byte ROP::VirtualMemoryBytes::getByteAtVirtualAddress(addressType vAddress) const {
    for (const auto& segm : this->readSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        addressType start = segm.startVirtualAddress;
        addressType end = segm.endVirtualAddress;
        addressType actualEnd = start + (unsigned long long)segm.bytes.size();

        if (start <= vAddress && vAddress < actualEnd) {
            return segm.bytes[vAddress - start];
        }
        else if (start <= vAddress && vAddress < end) {
            return (byte)0;
        }
    }

    LogWarn("Bad query in Virtual Memory! Can't find address: %llu (0x%llx)\n", vAddress, vAddress);
    return (byte)0;
}

std::vector<ROP::addressType>
ROP::VirtualMemoryBytes::matchBytesInVirtualMemory(const ROP::byteSequence& targetBytes) {
    assertMessage(targetBytes.size() != 0, "Got empty bytes sequence...");

    std::vector<addressType> matchedVirtualAddresses;

    for (const VirtualMemorySegmentBytes& segm : this->readSegments) {
        const byteSequence& segmentBytes = segm.bytes;
        int sizeSegmentBytes = (int)segmentBytes.size();
        int sizeTargetBytes = (int)targetBytes.size();

        for (int low = 0, high = sizeTargetBytes - 1; high < sizeSegmentBytes; ++low, ++high) {
            bool match = true;
            for (int idx = 0; idx < sizeTargetBytes; ++idx) {
                if (targetBytes[idx] != segmentBytes[low + idx]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                matchedVirtualAddresses.push_back(segm.startVirtualAddress + low);
            }
        }
    }

    return matchedVirtualAddresses;
}

std::vector<ROP::addressType>
ROP::VirtualMemoryBytes::matchStringInVirtualMemory(const char * const targetString) {
    assertMessage(targetString != NULL && *targetString != '\0', "Got empty string...");

    // Convert the string to a byte sequence.
    byteSequence bytes;
    for (const char *ptr = targetString; *ptr != '\0'; ++ptr) {
        bytes.push_back((ROP::byte)*ptr);
    }
    bytes.push_back('\0');

    return this->matchBytesInVirtualMemory(bytes);
}
