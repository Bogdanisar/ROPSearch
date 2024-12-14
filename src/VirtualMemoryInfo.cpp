#include "VirtualMemoryInfo.hpp"

#include <algorithm>

#include "ELFParser.hpp"


void ROP::VirtualMemoryInfo::buildExecutableSegments() {
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


void ROP::VirtualMemoryInfo::disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first) {
    assert(first < (int)segm.executableBytes.size());

    if (this->disassembledSegment.count(first) == 1) {
        // We have already analyzed the segment(s) starting at "first".
        return;
    }

    AssemblySyntax syntax = ROPConsts::InstructionASMSyntax;
    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;

    const byte *firstPtr = segm.executableBytes.data() + first;
    const unsigned long long firstAddr = segm.startVirtualAddress + first;
    int segmentSize = std::min(maxInstructionSize, (int)segm.executableBytes.size() - first);

    auto p = this->ic.convertInstructionSequenceToString(firstPtr, segmentSize, syntax, firstAddr, 1);
    std::vector<std::string>& instructions = p.first;
    unsigned totalDisassembledBytes = p.second;

    if (instructions.size() == 1) {
        int last = first + totalDisassembledBytes - 1;

        // The left-side index "first" corresponds uniquely to the [first, last] segment.
        // The segment disassembles into the "instructions[0]" instruction.
        this->disassembledSegment[first] = {last, instructions[0]};
    }
    else {
        // There is no "last" index such that [first, last] is a valid instruction.
        this->disassembledSegment[first] = {-1, ""};
    }
}

// Check if the given instruction is useful as the ending instruction of an instruction sequence.
static bool IsInstructionUsefulAsInstructionSequenceEnd(const ROP::byteSequence& bSeq, int first, int last) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    const int numBytes = (last - first + 1);

    // "ret" instruction.
    if (numBytes == 1 && bSeq[first] == 0xC3) { return true; }

    // "ret imm16" instruction.
    if (numBytes == 3 && bSeq[first] == 0xC2) { return true; }

    // // Relative "call" instruction.
    // if (numBytes == 5 && bSeq[first] == 0xE8) { return true; }

    return false;
}

void ROP::VirtualMemoryInfo::buildInstructionTrie(
    const VirtualMemoryExecutableSegment& segm,
    const int currRightSegmentIdx,
    ROP::InsSeqTrie::Node *currNode,
    const int currInstrSeqLength
) {
    if (currRightSegmentIdx < 0) {
        return;
    }
    if (currInstrSeqLength >= ROPConsts::MaxInstructionSequenceSize) {
        return;
    }

    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;
    int first = currRightSegmentIdx;
    int last = currRightSegmentIdx;

    for (; first >= 0 && (last - first + 1) <= maxInstructionSize; --first) {
        if (currInstrSeqLength == 0 && !IsInstructionUsefulAsInstructionSequenceEnd(segm.executableBytes, first, last)) {
            // This segment might represent a valid instruction but we don't consider it
            // to be useful as the ending instruction of an instruction sequence.
            continue;
        }

        this->disassembleSegmentBytes(segm, first);
        const auto& p = this->disassembledSegment[first];
        int actualLastIndex = p.first;

        // Check if the byte sequence between [first, last] is good.
        // (check if it disassembles into exactly one instruction)
        bool currSegmentIsGood = (actualLastIndex != -1 && last == actualLastIndex);
        if (!currSegmentIsGood) {
            // Bad segment (no instructions, too many instructions or bad bytes).
            continue;
        }

        // Insert the instruction at this segment into the trie;
        const std::string& instruction = p.second;
        unsigned long long vAddress = segm.startVirtualAddress + first;
        auto nextNode = this->instructionTrie.addInstruction(instruction, vAddress, currNode);

        // And then recurse.
        this->buildInstructionTrie(segm, first - 1, nextNode, currInstrSeqLength + 1);
    }
}

void ROP::VirtualMemoryInfo::buildInstructionTrie() {
    for (const VirtualMemoryExecutableSegment& segm : this->executableSegments) {
        for (int rightIdx = (int)segm.executableBytes.size()-1; rightIdx >= 0; --rightIdx) {
            this->buildInstructionTrie(segm, rightIdx, this->instructionTrie.root, 0);
        }

        this->disassembledSegment.clear();
    }
}

ROP::VirtualMemoryInfo::VirtualMemoryInfo(int processPid)
: vmSegmMapping(processPid) {
    this->buildExecutableSegments();
    this->buildInstructionTrie();
}


const ROP::VirtualMemoryMapping& ROP::VirtualMemoryInfo::getVMSegmMapping() const {
    return this->vmSegmMapping;
}

const std::vector<ROP::VirtualMemoryExecutableSegment>& ROP::VirtualMemoryInfo::getExecutableSegments() const {
    return this->executableSegments;
}

bool ROP::VirtualMemoryInfo::isValidVirtualAddressInExecutableSegment(unsigned long long vAddress) const {
    for (const auto& execSegm : this->executableSegments) {
        if (execSegm.startVirtualAddress <= vAddress && vAddress < execSegm.endVirtualAddress) {
            return true;
        }
    }

    return false;
}

ROP::byte ROP::VirtualMemoryInfo::getByteAtVirtualAddress(unsigned long long vAddress) const {
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

    printf("Can't find the given virtual address in the loaded Virtual Memory of executable code!\n");
    printf("Bad address = %llu (0x%llx)\n", vAddress, vAddress);
    return (byte)0;
}

std::vector<unsigned long long>
ROP::VirtualMemoryInfo::matchBytesInVirtualMemory(ROP::byteSequence bytes) {
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

std::vector<unsigned long long>
ROP::VirtualMemoryInfo::matchInstructionSequenceInVirtualMemory(std::string origInstructionSequenceAsm, AssemblySyntax origSyntax) {
    // Normalize the instruction sequence,
    // so that we are sure it looks exactly like what we have in the internal Trie.
    std::vector<std::string> instructions = this->ic.normalizeInstructionAsm(origInstructionSequenceAsm, origSyntax);

    return this->instructionTrie.hasInstructionSequence(instructions);
}

std::vector< std::pair<unsigned long long, std::vector<std::string>> >
ROP::VirtualMemoryInfo::getInstructionSequences() const {
    return this->instructionTrie.getTrieContent();
}
