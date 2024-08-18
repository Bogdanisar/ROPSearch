#include "VirtualMemoryInfo.hpp"

#include <algorithm>

#include "ELFParser.hpp"


void ROOP::VirtualMemoryInfo::buildExecutableSegments() {
    // This is used as an optimization in case there are multiple executable segments for the same ELF path.
    // (Otherwise, we would need to create an ELFParser multiple times for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    const std::vector<VirtualMemorySegmentMapping>& allSegmentMaps = this->vaSegmMapping.getSegmentMaps();
    for (const VirtualMemorySegmentMapping& segmentMap : allSegmentMaps) {
        if (!ELFParser::elfPathIsAcceptable(segmentMap.path)) {
            continue;
        }

        bool isExecutable = (segmentMap.rightsMask & (unsigned int)ROOP::VirtualMemorySegmentMapping::SegmentRights::EXECUTE);
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


void ROOP::VirtualMemoryInfo::disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first) {
    assert(first < (int)segm.executableBytes.size());

    if (this->disassembledSegment.count(first) == 1) {
        // We have already analyzed the segment(s) starting at "first".
        return;
    }

    AssemblySyntax syntax = ROOPConsts::InstructionASMSyntax;
    const int maxInstructionSize = ROOPConsts::MaxInstructionBytesCount;

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
static bool IsInstructionUsefulAsInstructionSequenceEnd(const ROOP::byteSequence& bSeq, int first, int last) {
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

void ROOP::VirtualMemoryInfo::buildInstructionTrie(
    const VirtualMemoryExecutableSegment& segm,
    const int currRightSegmentIdx,
    ROOP::InsSeqTrie::Node *currNode,
    const int currInstrSeqLength
) {
    if (currRightSegmentIdx < 0) {
        return;
    }
    if (currInstrSeqLength >= ROOPConsts::MaxInstructionSequenceSize) {
        return;
    }

    const int maxInstructionSize = ROOPConsts::MaxInstructionBytesCount;
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
        unsigned long long vaAddress = segm.startVirtualAddress + first;
        auto nextNode = this->instructionTrie.addInstruction(instruction, vaAddress, currNode);

        // And then recurse.
        this->buildInstructionTrie(segm, first - 1, nextNode, currInstrSeqLength + 1);
    }
}

void ROOP::VirtualMemoryInfo::buildInstructionTrie() {
    for (const VirtualMemoryExecutableSegment& segm : this->executableSegments) {
        for (int rightIdx = (int)segm.executableBytes.size()-1; rightIdx >= 0; --rightIdx) {
            this->buildInstructionTrie(segm, rightIdx, this->instructionTrie.root, 0);
        }

        this->disassembledSegment.clear();
    }
}

ROOP::VirtualMemoryInfo::VirtualMemoryInfo(int processPid)
: vaSegmMapping(processPid) {
    this->buildExecutableSegments();
    this->buildInstructionTrie();
}


const ROOP::VirtualMemoryMapping& ROOP::VirtualMemoryInfo::getVASegmMapping() const {
    return this->vaSegmMapping;
}

const std::vector<ROOP::VirtualMemoryExecutableSegment>& ROOP::VirtualMemoryInfo::getExecutableSegments() const {
    return this->executableSegments;
}

bool ROOP::VirtualMemoryInfo::isValidVAAddressInExecutableSegment(unsigned long long vaAddress) const {
    for (const auto& execSegm : this->executableSegments) {
        if (execSegm.startVirtualAddress <= vaAddress && vaAddress < execSegm.endVirtualAddress) {
            return true;
        }
    }

    return false;
}

ROOP::byte ROOP::VirtualMemoryInfo::getByteAtVAAddress(unsigned long long vaAddress) const {
    for (const auto& execSegm : this->executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        unsigned long long start = execSegm.startVirtualAddress;
        unsigned long long end = execSegm.endVirtualAddress;
        unsigned long long actualEnd = start + (unsigned long long)execSegm.executableBytes.size();

        if (start <= vaAddress && vaAddress < actualEnd) {
            return execSegm.executableBytes[vaAddress - start];
        }
        else if (start <= vaAddress && vaAddress < end) {
            return (byte)0;
        }
    }

    printf("Can't find the given virtual address in the loaded Virtual Memory of executable code!\n");
    printf("Bad address = %llu (0x%llx)\n", vaAddress, vaAddress);
    return (byte)0;
}

std::vector<unsigned long long>
ROOP::VirtualMemoryInfo::matchInstructionSequenceInVirtualMemory(ROOP::byteSequence instructionSequence) {
    assertMessage(instructionSequence.size() != 0, "Got empty instruction sequence...");

    std::vector<unsigned long long> matchedVirtualAddresses;

    for (const VirtualMemoryExecutableSegment& execSegm : this->executableSegments) {
        const byteSequence& segmentBytes = execSegm.executableBytes;
        int sizeCodeBytes = (int)segmentBytes.size();
        int sizeInsSeqBytes = (int)instructionSequence.size();

        for (int low = 0, high = sizeInsSeqBytes - 1; high < sizeCodeBytes; ++low, ++high) {
            bool match = true;
            for (int idx = 0; idx < sizeInsSeqBytes; ++idx) {
                if (instructionSequence[idx] != segmentBytes[low + idx]) {
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
ROOP::VirtualMemoryInfo::matchInstructionSequenceInVirtualMemory(std::string origInstructionSequenceAsm, AssemblySyntax origSyntax) {
    // Normalize the instruction sequence,
    // so that we are sure it looks exactly like what we have in the internal Trie.
    std::vector<std::string> instructions = this->ic.normalizeInstructionAsm(origInstructionSequenceAsm, origSyntax);

    return this->instructionTrie.hasInstructionSequence(instructions);
}

std::vector< std::pair<unsigned long long, std::vector<std::string>> >
ROOP::VirtualMemoryInfo::getInstructionSequences() const {
    return this->instructionTrie.getTrieContent();
}
