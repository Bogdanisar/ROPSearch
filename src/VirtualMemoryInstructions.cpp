#include "VirtualMemoryInstructions.hpp"

#include <algorithm>


// Declaration for static member, with default value.
int ROP::VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = 10;

void ROP::VirtualMemoryInstructions::disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first) {
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

void ROP::VirtualMemoryInstructions::buildInstructionTrie(
    const VirtualMemoryExecutableSegment& segm,
    const int currRightSegmentIdx,
    ROP::InsSeqTrie::Node *currNode,
    const int currInstrSeqLength
) {
    if (currRightSegmentIdx < 0) {
        return;
    }
    if (currInstrSeqLength >= VirtualMemoryInstructions::MaxInstructionsInInstructionSequence) {
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

void ROP::VirtualMemoryInstructions::buildInstructionTrie() {
    for (const VirtualMemoryExecutableSegment& segm : this->vmExecBytes.getExecutableSegments()) {
        for (int rightIdx = (int)segm.executableBytes.size()-1; rightIdx >= 0; --rightIdx) {
            this->buildInstructionTrie(segm, rightIdx, this->instructionTrie.root, 0);
        }

        this->disassembledSegment.clear();
    }
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(int processPid)
: vmExecBytes(processPid) {
    this->buildInstructionTrie();
}


std::vector<unsigned long long>
ROP::VirtualMemoryInstructions::matchInstructionSequenceInVirtualMemory(std::string origInstructionSequenceAsm, AssemblySyntax origSyntax) {
    // Normalize the instruction sequence,
    // so that we are sure it looks exactly like what we have in the internal Trie.
    std::vector<std::string> instructions = this->ic.normalizeInstructionAsm(origInstructionSequenceAsm,
                                                                             origSyntax,
                                                                             ROP::ROPConsts::InstructionASMSyntax);

    return this->instructionTrie.hasInstructionSequence(instructions);
}

std::vector< std::pair<unsigned long long, std::vector<std::string>> >
ROP::VirtualMemoryInstructions::getInstructionSequences() const {
    return this->instructionTrie.getTrieContent();
}
