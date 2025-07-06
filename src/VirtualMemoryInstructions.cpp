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
static inline ROP::PrefixByteX86 ByteIsInstructionPrefix(ROP::byte b) {
    switch (b) {
        // LOCK prefix
        case 0xF0: return ROP::PrefixByteX86::LOCK;

        // REPNE/REPNZ prefix
        case 0xF2: return ROP::PrefixByteX86::REPNE;

        // REP or REPE/REPZ prefix
        case 0xF3: return ROP::PrefixByteX86::REP;

        // CS segment override / Branch not taken
        case 0x2E: return ROP::PrefixByteX86::CS_SEGMENT_OVERRIDE;

        // SS segment override
        case 0x36: return ROP::PrefixByteX86::SS_SEGMENT_OVERRIDE;

        // DS segment override / Branch taken
        case 0x3E: return ROP::PrefixByteX86::DS_SEGMENT_OVERRIDE;

        // ES segment override
        case 0x26: return ROP::PrefixByteX86::ES_SEGMENT_OVERRIDE;

        // FS segment override
        case 0x64: return ROP::PrefixByteX86::FS_SEGMENT_OVERRIDE;

        // GS segment override
        case 0x65: return ROP::PrefixByteX86::GS_SEGMENT_OVERRIDE;

        // Operand-size override prefix
        case 0x66: return ROP::PrefixByteX86::OPERAND_SIZE_OVERRIDE;

        // Address-size override prefix
        case 0x67: return ROP::PrefixByteX86::ADDRESS_SIZE_OVERRIDE;

        default: return ROP::PrefixByteX86::NONE;
    }
}

/** Check if this byte value is valid as a REX byte. */
static inline bool ByteIsValidRexByte(ROP::byte b) {
    ROP::byte mostSignificant4Bits = (b >> 4);
    return (mostSignificant4Bits == 0b0100);
    // Alternatively:
    // return (0x40 <= b && b <= 0x4F);
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
 * Check if this is a relative "jmp" instruction ("relative" meaning "RIP = RIP + offset").
 * In other words, check if this is a "JMP rel8", "JMP rel16" or "JMP rel32" instruction.
 * @note As an asm string, this is represented as "jmp finalAddress",
 *       even though only the offset is encoded.
 */
static inline bool BytesAreDirectRelativeJmpInstruction32bit(const ROP::byteSequence& bSeq,
                                                             int first, int last,
                                                             int prefixBytesMask,
                                                             int32_t *offset = NULL) {
    const int numBytes = (last - first + 1);

    if (numBytes == (1 + 1) && bSeq[first] == 0xEB) {
        // Is "JMP rel8" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int8_t>(bSeq.data() + first + 1);
        }
        return true;
    }

    int sizeOverrideVal = (int)ROP::PrefixByteX86::OPERAND_SIZE_OVERRIDE;
    bool hasSizeOverridePrefix = ((prefixBytesMask & sizeOverrideVal) != 0);
    if (!hasSizeOverridePrefix && numBytes == (1 + 4) && bSeq[first] == 0xE9) {
        // Is "JMP rel32" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int32_t>(bSeq.data() + first + 1);
        }
        return true;
    }

    if (hasSizeOverridePrefix && numBytes == (1 + 2) && bSeq[first] == 0xE9) {
        // Is "JMP rel16" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int16_t>(bSeq.data() + first + 1);
        }
        return true;
    }

    return false;
}

/**
 * The same as `BytesAreDirectRelativeJmpInstruction32bit()`,
 * but try parsing the prefix bytes as well.
 */
static inline bool BytesAreDirectRelativeJmpInstruction32bitWithPrefixParse(const ROP::byteSequence& bSeq,
                                                                            int first, int last,
                                                                            int prefixBytesMask,
                                                                            int32_t *offset = NULL) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    // Try to parse a prefix byte.
    if (first < last) { // at least 2 bytes.
        ROP::PrefixByteX86 currPrefixByte = ByteIsInstructionPrefix(bSeq[first]);
        if (currPrefixByte != ROP::PrefixByteX86::NONE) {
            int newPrefixBytesMask = prefixBytesMask | (int)currPrefixByte;
            if (BytesAreDirectRelativeJmpInstruction32bitWithPrefixParse(bSeq,
                                                                         first + 1, last,
                                                                         newPrefixBytesMask,
                                                                         offset)) {
                return true;
            }
        }
    }

    if (BytesAreDirectRelativeJmpInstruction32bit(bSeq, first, last, prefixBytesMask, offset)) {
        return true;
    }

    return false;
}

/**
 * Check if this is a relative "jmp" instruction ("relative" meaning "RIP = RIP + offset").
 * In other words, check if this is a "JMP rel8" or "JMP rel32" instruction.
 * The "JMP rel16" instruction doesn't seem to be possible on x64.
 * @note As an asm string, this is represented as "jmp finalAddress",
 *       even though only the offset is encoded.
 */
static inline bool BytesAreDirectRelativeJmpInstruction64bit(const ROP::byteSequence& bSeq,
                                                             int first, int last,
                                                             int prefixBytesMask,
                                                             int32_t *offset = NULL) {
    UNUSED(prefixBytesMask);
    const int numBytes = (last - first + 1);

    if (numBytes == (1 + 1) && bSeq[first] == 0xEB) {
        // Is "JMP rel8" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int8_t>(bSeq.data() + first + 1);
        }
        return true;
    }

    // The operand-size override prefix byte doesn't affect this instruction on x64,
    // so the "JMP rel16" instruction is not possible on 64bit.

    if (numBytes == (1 + 4) && bSeq[first] == 0xE9) {
        // Is "JMP rel32" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int32_t>(bSeq.data() + first + 1);
        }
        return true;
    }

    if (first < last && ByteIsValidRexByte(bSeq[first])
        && BytesAreDirectRelativeJmpInstruction64bit(bSeq, first + 1, last, prefixBytesMask, offset)) {
        // Check if the instruction opcode is preceded by "REX" bytes.
        return true;
    }

    return false;
}

/**
 * The same as `BytesAreDirectRelativeJmpInstruction64bit()`,
 * but try parsing the prefix bytes as well.
 */
static inline bool BytesAreDirectRelativeJmpInstruction64bitWithPrefixParse(const ROP::byteSequence& bSeq,
                                                                            int first, int last,
                                                                            int prefixBytesMask,
                                                                            int32_t *offset = NULL) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    // Try to parse a prefix byte.
    if (first < last) { // at least 2 bytes.
        ROP::PrefixByteX86 currPrefixByte = ByteIsInstructionPrefix(bSeq[first]);
        if (currPrefixByte != ROP::PrefixByteX86::NONE) {
            int newPrefixBytesMask = prefixBytesMask | (int)currPrefixByte;
            if (BytesAreDirectRelativeJmpInstruction64bitWithPrefixParse(bSeq,
                                                                         first + 1, last,
                                                                         newPrefixBytesMask,
                                                                         offset)) {
                return true;
            }
        }
    }

    if (BytesAreDirectRelativeJmpInstruction64bit(bSeq, first, last, prefixBytesMask, offset)) {
        return true;
    }

    return false;
}

/**
 * Check if this is an absolute "jmp" instruction ("absolute" meaning "RIP = newAddress").
 * In other words, check if this is a "JMP ptr16:16" or "JMP ptr16:32" instruction.
 * This instruction type seems to be valid on x86_32, but not x86_64.
 */
static inline bool BytesAreDirectAbsoluteJmpInstruction32bit(const ROP::byteSequence& bSeq,
                                                             int first, int last,
                                                             int prefixBytesMask) {
    const int numBytes = (last - first + 1);
    int sizeOverrideVal = (int)ROP::PrefixByteX86::OPERAND_SIZE_OVERRIDE;
    bool hasSizeOverridePrefix = ((prefixBytesMask & sizeOverrideVal) != 0);

    if (!hasSizeOverridePrefix && numBytes == (1 + 2 + 4) && bSeq[first] == 0xEA) {
        // Is "JMP ptr16:32" instruction.
        return true;
    }

    if (hasSizeOverridePrefix && numBytes == (1 + 2 + 2) && bSeq[first] == 0xEA) {
        // Is "JMP ptr16:16" instruction.
        return true;
    }

    return false;
}

/**
 * Check if the given bytes represent an instruction
 * that is useful as the ending instruction of an instruction sequence.
 */
static inline bool BytesAreUsefulInstructionAtSequenceEnd(const ROP::byteSequence& bSeq,
                                                          int first, int last) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    if (first < last // at least 2 bytes
        && ByteIsInstructionPrefix(bSeq[first]) != ROP::PrefixByteX86::NONE
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
static inline bool BytesAreBadInstructionInsideSequence(const ROP::byteSequence& bSeq,
                                                        int first, int last,
                                                        int prefixBytesMask,
                                                        ROP::BitSizeClass bsc) {
    assert(0 <= first && first < (int)bSeq.size());
    assert(0 <= last && last < (int)bSeq.size());
    assert(first <= last);

    // Try to parse a prefix byte.
    if (first < last) { // at least 2 bytes.
        ROP::PrefixByteX86 currPrefixByte = ByteIsInstructionPrefix(bSeq[first]);
        if (currPrefixByte != ROP::PrefixByteX86::NONE) {
            int newPrefixBytesMask = prefixBytesMask | (int)currPrefixByte;
            if (BytesAreBadInstructionInsideSequence(bSeq,
                                                     first + 1, last,
                                                     newPrefixBytesMask,
                                                     bsc)) {
                return true;
            }
        }
    }

    if (BytesAreRetInstruction(bSeq, first, last)) {
        return true;
    }

    if (BytesAreRelativeCallInstruction64bit(bSeq, first, last)) {
        return true;
    }

    if (bsc == ROP::BitSizeClass::BIT32
        && BytesAreDirectRelativeJmpInstruction32bit(bSeq, first, last, prefixBytesMask)) {
        return true;
    }
    if (bsc == ROP::BitSizeClass::BIT64
        && BytesAreDirectRelativeJmpInstruction64bit(bSeq, first, last, prefixBytesMask)) {
        return true;
    }
    if (bsc == ROP::BitSizeClass::BIT32
        && BytesAreDirectAbsoluteJmpInstruction32bit(bSeq, first, last, prefixBytesMask)) {
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

void ROP::VirtualMemoryInstructions::buildRelativeJmpMap(const VirtualMemoryExecutableSegment& segm) {
    // Function pointer for the relevant function for the bit size of the current architecture.
    auto BytesAreDirectRelativeJmpInstructionWithPrefixParse = BytesAreDirectRelativeJmpInstruction32bitWithPrefixParse;
    if (this->archBitSize == BitSizeClass::BIT64) {
        BytesAreDirectRelativeJmpInstructionWithPrefixParse = BytesAreDirectRelativeJmpInstruction64bitWithPrefixParse;
    }

    int lastValidIndex = (int)segm.executableBytes.size() - 1;
    for (int opcodeIdx = 0; opcodeIdx <= lastValidIndex; ++opcodeIdx) {
        ROP::byte currentByte = segm.executableBytes[opcodeIdx];
        // See if this byte has the right opcode value for one of the relative jmp instructions.
        if (currentByte == 0xEB || currentByte == 0xE9) {
            // We want to look around this byte for a sequence that encodes a jmp instruction.

            // Account for any possible prefix bytes.
            int smallestFirstIndex = std::max(0, opcodeIdx - 10);

            // Account for any possible offset bytes.
            int biggestLastIndex = std::min(opcodeIdx + 4, lastValidIndex);

            for (int first = smallestFirstIndex; first <= opcodeIdx; ++first) {
                for (int last = opcodeIdx + 1; last <= biggestLastIndex; ++last) {
                    int32_t offset;
                    if (BytesAreDirectRelativeJmpInstructionWithPrefixParse(segm.executableBytes,
                                                                            first, last,
                                                                            0,
                                                                            &offset)) {
                        addressType currVMAddress = segm.startVirtualAddress + first;
                        int currInstructionSize = (last - first + 1);
                        addressType newVMAddress = currVMAddress + currInstructionSize + offset;

                        this->jmpIndexesForAddress[newVMAddress].insert(first);

                        // Found match for [first, last]; `last` index is unique for a given `first` =>
                        // There's no need to keep increasing `last` and check other [first, ...] intervals.
                        break;
                    }
                }
            }
        }
    }
}

void ROP::VirtualMemoryInstructions::disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first) {
    assert(first < (int)segm.executableBytes.size());

    if (this->disassembledSegment.count(first) == 1) {
        // We have already analyzed the segment(s) starting at "first".
        return;
    }

    AssemblySyntax syntax = VirtualMemoryInstructions::innerAssemblySyntax;
    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;

    const byte *firstPtr = segm.executableBytes.data() + first;
    const addressType firstAddr = segm.startVirtualAddress + first;
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
    ROP::InsSeqTrie::Node *prevNode,
    const int prevInstrSeqLength
) {
    if (currRightSegmentIdx < 0) {
        return;
    }
    if (prevInstrSeqLength >= VirtualMemoryInstructions::MaxInstructionsInInstructionSequence) {
        return;
    }

    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;
    int first = currRightSegmentIdx;
    int last = currRightSegmentIdx;

    for (; first >= 0 && (last - first + 1) <= maxInstructionSize; --first) {
        if (prevInstrSeqLength == 0 && !BytesAreUsefulInstructionAtSequenceEnd(segm.executableBytes, first, last)) {
            // This index interval might represent a valid instruction but we don't consider it
            // to be useful as the ending instruction of an instruction sequence.
            continue;
        }

        if (prevInstrSeqLength > 0 && BytesAreBadInstructionInsideSequence(segm.executableBytes,
                                                                           first, last,
                                                                           0,
                                                                           this->archBitSize)) {
            // This index interval might represent a valid instruction but we don't consider it
            // to be a useful instruction inside of an instruction sequence.
            continue;
        }

        this->disassembleSegmentBytes(segm, first);
        const auto& p = this->disassembledSegment[first];
        int actualLastIndex = p.first;

        // Check if the byte sequence between [first, last] is valid and
        // disassembles into exactly one instruction.
        bool currSegmentIsGood = (actualLastIndex != -1 && last == actualLastIndex);
        if (!currSegmentIsGood) {
            // Bad segment (no instructions, too many instructions or bad bytes).
            continue;
        }

        // Grab the disassembled information for the instruction at the current segment.
        const std::string& currInstruction = p.second;
        RegisterInfo *currRegInfoPtr = NULL;
        if (VirtualMemoryInstructions::computeRegisterInfo) {
            currRegInfoPtr = &this->regInfoForSegment[first];
        }

        // Insert the instruction at this segment into the trie;
        addressType currVMAddress = segm.startVirtualAddress + first;
        auto currNode = this->instructionTrie.addInstruction(prevNode, currInstruction, currVMAddress, currRegInfoPtr);

        // And then recurse.
        const int currInstrSeqLength = prevInstrSeqLength + 1;
        this->buildInstructionTrie(segm, first - 1, currNode, currInstrSeqLength);
    }
}

void ROP::VirtualMemoryInstructions::buildInstructionTrie() {
    for (const VirtualMemoryExecutableSegment& segm : this->vmExecBytes.getExecutableSegments()) {
        this->buildRelativeJmpMap(segm);

        for (int rightIdx = (int)segm.executableBytes.size()-1; rightIdx >= 0; --rightIdx) {
            this->buildInstructionTrie(segm, rightIdx, this->instructionTrie.root, 0);
        }

        this->disassembledSegment.clear();
        this->regInfoForSegment.clear();
        this->jmpIndexesForAddress.clear();
    }
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(int processPid)
: vmExecBytes(processPid), ic(this->vmExecBytes.getProcessArchSize()) {
    this->archBitSize = this->vmExecBytes.getProcessArchSize();
    this->buildInstructionTrie();
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(const std::vector<std::string> execPaths,
                                                          const std::vector<addressType> baseAddresses)
: vmExecBytes(execPaths, baseAddresses), ic(this->vmExecBytes.getProcessArchSize()) {
    this->archBitSize = this->vmExecBytes.getProcessArchSize();
    this->buildInstructionTrie();
}

const ROP::VirtualMemoryExecutableBytes
ROP::VirtualMemoryInstructions::getExecutableBytes() const {
    return this->vmExecBytes;
}


std::vector<ROP::addressType>
ROP::VirtualMemoryInstructions::matchInstructionSequenceInVirtualMemory(std::string origInstructionSequenceAsm, AssemblySyntax origSyntax) {
    // Normalize the instruction sequence,
    // so that we are sure it looks exactly like what we have in the internal Trie.
    std::vector<std::string> instructions = this->ic.normalizeInstructionAsm(origInstructionSequenceAsm,
                                                                             origSyntax,
                                                                             VirtualMemoryInstructions::innerAssemblySyntax);

    return this->instructionTrie.hasInstructionSequence(instructions);
}

std::vector< std::pair<ROP::addressType, std::vector<std::string>> >
ROP::VirtualMemoryInstructions::getInstructionSequences(std::vector<std::vector<RegisterInfo>> *outRegInfo) const {
    assertMessage(outRegInfo == NULL || VirtualMemoryInstructions::computeRegisterInfo,
                  "Can't get the instruction sequences with added register info since "
                  "the instruction trie wasn't built with that extra information.");
    return this->instructionTrie.getTrieContent(outRegInfo);
}

#pragma endregion Methods
