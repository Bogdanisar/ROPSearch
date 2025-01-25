#include "VirtualMemoryInstructions.hpp"

#include <algorithm>


// Declaration for static member, with default value.
int ROP::VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = 10;

// Declaration for static member, with default value.
ROP::AssemblySyntax ROP::VirtualMemoryInstructions::innerAssemblySyntax = ROP::AssemblySyntax::Intel;

// Declaration for static member, with default value.
bool ROP::VirtualMemoryInstructions::computeRegisterInfo = false;


#pragma region Parse key instructions
#if false
int ________Parse_key_instructions________;
#endif

/** Check if this byte represents an instruction prefix byte in x86. */
static inline bool ByteIsInstructionPrefix(ROP::byte b) {
    switch (b) {
        // LOCK prefix
        case 0xF0: return true;

        // REPNE/REPNZ prefix
        case 0xF2: return true;

        // REP or REPE/REPZ prefix
        case 0xF3: return true;

        // CS segment override / Branch not taken
        case 0x2E: return true;

        // SS segment override
        case 0x36: return true;

        // DS segment override / Branch taken
        case 0x3E: return true;

        // ES segment override
        case 0x26: return true;

        // FS segment override
        case 0x64: return true;

        // GS segment override
        case 0x65: return true;

        // Operand-size override prefix
        case 0x66: return true;

        // Address-size override prefix
        case 0x67: return true;

        default: return false;
    }
}

static inline bool BytesAreRetInstruction(const ROP::byteSequence& bSeq, int first, int last) {
    const int numBytes = (last - first + 1);

    // "ret" instruction.
    if (numBytes == 1 && bSeq[first] == 0xC3) { return true; }

    // "ret imm16" instruction.
    if (numBytes == 3 && bSeq[first] == 0xC2) { return true; }

    return false;
}

/**
 * Check if this is a relative "call" instruction ("relative" meaning "RIP = RIP + offset").
 * @note As an asm string, this is represented as "call finalAddress",
 *       even though only the offset is encoded.
 */
static inline bool BytesAreRelativeCallInstruction64bit(const ROP::byteSequence& bSeq, int first, int last) {
    const int numBytes = (last - first + 1);
    return (numBytes == 5 && bSeq[first] == 0xE8);
}

/**
 * Check if the given bytes represent an instruction
 * that is useful as the ending instruction of an instruction sequence.
 */
static inline bool BytesAreUsefulInstructionAtSequenceEnd(const ROP::byteSequence& bSeq, int first, int last) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    if (first < last && ByteIsInstructionPrefix(bSeq[first])
        && BytesAreUsefulInstructionAtSequenceEnd(bSeq, first + 1, last)) {
        return true;
    }

    if (BytesAreRetInstruction(bSeq, first, last)) {
        return true;
    }

    // TODO: Add more.

    return false;
}

/**
 * Check if the given bytes represent an instruction
 * that is unhelpful inside of an instruction sequence,
 * where "inside" means anywhere except the last instruction.
 */
static bool BytesAreBadInstructionInsideSequence(const ROP::byteSequence& bSeq, int first, int last) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    if (first < last && ByteIsInstructionPrefix(bSeq[first])
        && BytesAreBadInstructionInsideSequence(bSeq, first + 1, last)) {
        return true;
    }

    if (BytesAreRetInstruction(bSeq, first, last)) {
        return true;
    }

    if (BytesAreRelativeCallInstruction64bit(bSeq, first, last)) {
        return true;
    }

    // TODO: Add more

    return false;
}

#pragma endregion Parse key instructions


#pragma region Methods
#if false
int ________Methods________;
#endif

void ROP::VirtualMemoryInstructions::disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first) {
    assert(first < (int)segm.executableBytes.size());

    if (this->disassembledSegment.count(first) == 1) {
        // We have already analyzed the segment(s) starting at "first".
        return;
    }

    AssemblySyntax syntax = VirtualMemoryInstructions::innerAssemblySyntax;
    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;

    const byte *firstPtr = segm.executableBytes.data() + first;
    const unsigned long long firstAddr = segm.startVirtualAddress + first;
    int segmentSize = std::min(maxInstructionSize, (int)segm.executableBytes.size() - first);

    std::vector<std::string> instructions;
    unsigned totalDisassembledBytes;

    std::vector<RegisterInfo> *regInfoVectorPtr = NULL;
    if (VirtualMemoryInstructions::computeRegisterInfo) {
        regInfoVectorPtr = &(this->auxRegInfoVector);
    }

    totalDisassembledBytes = this->ic.convertInstructionSequenceToString(firstPtr,
                                                                         segmentSize,
                                                                         syntax,
                                                                         firstAddr,
                                                                         1,
                                                                         &instructions,
                                                                         regInfoVectorPtr);

    if (instructions.size() == 1) {
        int last = first + totalDisassembledBytes - 1;

        // The left-side index "first" corresponds uniquely to the [first, last] segment.
        // The segment disassembles into the "instructions[0]" instruction.
        this->disassembledSegment[first] = {last, instructions[0]};

        if (VirtualMemoryInstructions::computeRegisterInfo) {
            this->regInfoForSegment[first] = this->auxRegInfoVector[0];
            this->auxRegInfoVector.clear();
        }
    }
    else {
        // There is no "last" index such that [first, last] is a valid instruction.
        this->disassembledSegment[first] = {-1, ""};
    }
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
        if (currInstrSeqLength == 0 && !BytesAreUsefulInstructionAtSequenceEnd(segm.executableBytes, first, last)) {
            // This index interval might represent a valid instruction but we don't consider it
            // to be useful as the ending instruction of an instruction sequence.
            continue;
        }

        if (currInstrSeqLength > 0 && BytesAreBadInstructionInsideSequence(segm.executableBytes, first, last)) {
            // This index interval might represent a valid instruction but we don't consider it
            // to be a useful instruction inside of an instruction sequence.
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

        RegisterInfo *regInfoPtr = NULL;
        if (VirtualMemoryInstructions::computeRegisterInfo) {
            regInfoPtr = &this->regInfoForSegment[first];
        }

        auto nextNode = this->instructionTrie.addInstruction(instruction, vAddress, currNode, regInfoPtr);

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
        this->regInfoForSegment.clear();
    }
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(int processPid)
: vmExecBytes(processPid) {
    this->buildInstructionTrie();
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(const std::vector<std::string> execPaths,
                                                          const std::vector<unsigned long long> baseAddresses)
: vmExecBytes(execPaths, baseAddresses) {
    this->buildInstructionTrie();
}


std::vector<unsigned long long>
ROP::VirtualMemoryInstructions::matchInstructionSequenceInVirtualMemory(std::string origInstructionSequenceAsm, AssemblySyntax origSyntax) {
    // Normalize the instruction sequence,
    // so that we are sure it looks exactly like what we have in the internal Trie.
    std::vector<std::string> instructions = this->ic.normalizeInstructionAsm(origInstructionSequenceAsm,
                                                                             origSyntax,
                                                                             VirtualMemoryInstructions::innerAssemblySyntax);

    return this->instructionTrie.hasInstructionSequence(instructions);
}

std::vector< std::pair<unsigned long long, std::vector<std::string>> >
ROP::VirtualMemoryInstructions::getInstructionSequences(std::vector<std::vector<RegisterInfo>> *outRegInfo) const {
    assertMessage(outRegInfo == NULL || VirtualMemoryInstructions::computeRegisterInfo,
                  "Can't get the instruction sequences with added register info since "
                  "the instruction trie wasn't built with that extra information.");
    return this->instructionTrie.getTrieContent(outRegInfo);
}

#pragma endregion Methods
