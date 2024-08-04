#include "VirtualMemoryInfo.hpp"

#include <algorithm>

#include "ELFParser.hpp"
#include "InstructionConverter.hpp"


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


void ROOP::VirtualMemoryInfo::disassembleSegmentBytes(
    const VirtualMemoryExecutableSegment& segm,
    const int first,
    const int last
) {
    std::pair<int,int> segment = {first, last};

    if (this->disassembledSegments.count(segment) == 1) {
        // We have already analyzed this segment.
        // The information is available in the inner data structures.
        return;
    }

    AssemblySyntax syntax = ROOPConsts::InstructionASMSyntax;
    const byte *firstPtr = segm.executableBytes.data() + first;
    int segmentSize = (last - first + 1);

    auto p = InstructionConverter::convertInstructionSequenceToString(firstPtr, segmentSize, syntax);
    std::vector<std::string>& instructions = p.first;
    unsigned totalDisassembledBytes = p.second;
    bool allBytesWereParsedSuccessfully = ((unsigned)segmentSize == totalDisassembledBytes);

    if (instructions.size() == 1 && allBytesWereParsedSuccessfully) {
        // Perfect. We want a segment to disassemble into exactly one instruction.
        this->segmentToInstruction[segment] = instructions[0];
    }

    this->disassembledSegments.insert(segment);
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
        std::pair<int,int> segment = {first, last};
        this->disassembleSegmentBytes(segm, first, last);

        if (this->segmentToInstruction.count(segment) == 1) {
            const std::string& instruction = segmentToInstruction[segment];

            // Insert the instruction at this segment into the trie;
            unsigned long long vaAddress = segm.startVirtualAddress + first;
            auto nextNode = this->instructionTrie.addInstruction(instruction, vaAddress, currNode);

            // And then recurse.
            this->buildInstructionTrie(segm, first - 1, nextNode, currInstrSeqLength + 1);
        }
        else {
            // The byte sequence between [first, last] is bad (no instructions, too many instructions or bad bytes);
            continue;
        }
    }
}

void ROOP::VirtualMemoryInfo::buildInstructionTrie() {
    for (const VirtualMemoryExecutableSegment& segm : this->executableSegments) {
        this->disassembledSegments.clear();
        this->segmentToInstruction.clear();

        for (int rightIdx = (int)segm.executableBytes.size()-1; rightIdx >= 0; --rightIdx) {
            if (segm.executableBytes[rightIdx] == (byte)'\xC3') {
                // Start only if the last instruction in the sequence is a "ret";
                this->buildInstructionTrie(segm, rightIdx, this->instructionTrie.root, 0);
            }
        }
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
    std::vector<std::string> instructions = InstructionConverter::normalizeInstructionAsm(origInstructionSequenceAsm, origSyntax);

    return this->instructionTrie.hasInstructionSequence(instructions);
}
