#include "VirtualMemoryInstructions.hpp"

#include <algorithm>

#include "ByteParsingX86.hpp"


// Declarations for static members, with default values.

int ROP::VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = 10;
bool ROP::VirtualMemoryInstructions::SearchForSequencesWithDirectRelativeJumpsInTheMiddle = true;
bool ROP::VirtualMemoryInstructions::IgnoreOutputSequencesThatStartWithDirectRelativeJumps = true;
ROP::AssemblySyntax ROP::VirtualMemoryInstructions::innerAssemblySyntax = ROP::AssemblySyntax::Intel;
bool ROP::VirtualMemoryInstructions::computeRegisterInfo = false;


#pragma region Methods
#if false
int ________Methods________;
#endif

void ROP::VirtualMemoryInstructions::buildRelativeJmpMap(const VirtualMemorySegmentBytes& segm) {
    // Function pointer for the relevant function for the bit size of the current architecture.
    auto BytesAreDirectRelativeJmpInstructionWithPrefixParse = BytesAreDirectRelativeJmpInstruction32bitWithPrefixParse;
    if (this->archBitSize == BitSizeClass::BIT64) {
        BytesAreDirectRelativeJmpInstructionWithPrefixParse = BytesAreDirectRelativeJmpInstruction64bitWithPrefixParse;
    }

    int lastValidIndex = (int)segm.bytes.size() - 1;
    for (int opcodeIdx = 0; opcodeIdx <= lastValidIndex; ++opcodeIdx) {
        ROP::byte currentByte = segm.bytes[opcodeIdx];
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
                    if (BytesAreDirectRelativeJmpInstructionWithPrefixParse(segm.bytes,
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

void ROP::VirtualMemoryInstructions::disassembleSegmentBytes(const VirtualMemorySegmentBytes& segm, const int first) {
    assert(first < (int)segm.bytes.size());

    if (this->disassembledSegment.count(first) == 1) {
        // We have already analyzed the segment(s) starting at "first".
        return;
    }

    AssemblySyntax syntax = VirtualMemoryInstructions::innerAssemblySyntax;
    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;

    const byte *firstPtr = segm.bytes.data() + first;
    const addressType firstAddr = segm.startVirtualAddress + first;
    int segmentSize = std::min(maxInstructionSize, (int)segm.bytes.size() - first);

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


void ROP::VirtualMemoryInstructions::extendInstructionSequenceThroughDirectlyPrecedingInstructions(
    const VirtualMemorySegmentBytes& segm,
    InsSeqTrie::Node *prevNode,
    const int prevFirstIndex,
    const addressType prevVMAddress,
    const int prevInstrSeqLength
) {
    UNUSED(prevVMAddress);
    // Try to extend the current instruction sequence by looking for a directly preceding instruction.

    // The current instruction should have the last byte right before the previous instruction.
    const int currRightSegmentIdx = prevFirstIndex - 1;

    if (currRightSegmentIdx < 0) {
        // We went too far back.
        return;
    }

    if (prevInstrSeqLength >= VirtualMemoryInstructions::MaxInstructionsInInstructionSequence) {
        // The sequence is too long.
        return;
    }

    const int maxInstructionSize = ROPConsts::MaxInstructionBytesCount;
    int first = currRightSegmentIdx;
    const int last = currRightSegmentIdx;

    for (; first >= 0 && (last - first + 1) <= maxInstructionSize; --first) {
        if (prevInstrSeqLength == 0 && !BytesAreUsefulInstructionAtSequenceEnd(segm.bytes, first, last)) {
            // This index interval might represent a valid instruction but we don't consider it
            // to be useful as the ending instruction of an instruction sequence.
            continue;
        }

        if (prevInstrSeqLength > 0 && BytesAreBadInstructionInsideSequence(segm.bytes,
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

        // Recurse and try to extend the instruction sequence further.
        const int currInstrSeqLength = prevInstrSeqLength + 1;
        this->extendInstructionSequenceAndAddToTrie(segm, currNode, first, currVMAddress, currInstrSeqLength);
    }
}

void ROP::VirtualMemoryInstructions::extendInstructionSequenceThroughRelativeJmpInstructions(
    const VirtualMemorySegmentBytes& segm,
    InsSeqTrie::Node *prevNode,
    const int prevFirstIndex,
    const addressType prevVMAddress,
    const int prevInstrSeqLength
) {
    UNUSED(prevFirstIndex);
    // Try to extend this instruction sequence by looking for a relative jump to the current instruction.

    if (prevInstrSeqLength == 0) {
        // We can't have a relative jump instruction be the ending instruction in the sequence.
        // Not only would that not be useful, there's also no previous place to jump to.
        return;
    }

    if (prevInstrSeqLength >= VirtualMemoryInstructions::MaxInstructionsInInstructionSequence) {
        // The sequence is too long.
        return;
    }

    const std::set<int>& jmpIndexSet = this->jmpIndexesForAddress[prevVMAddress];
    if (jmpIndexSet.size() == 0) {
        // There aren't any relative jmp instructions that jump to the current address.
        return;
    }

    for (int jmpFirstIndex : jmpIndexSet) {
        // Disassemble the bytes for the jmp instruction.
        this->disassembleSegmentBytes(segm, jmpFirstIndex);

        // Retrieve the disassembled information.
        const auto& p = this->disassembledSegment[jmpFirstIndex];
        int jmpLastIndex = p.first;
        std::string jmpInstruction = p.second + " -->";
        if (jmpLastIndex == -1) {
            // Theoretically, this shouldn't happen if our byte-parsing methods:
            // - BytesAreDirectRelativeJmpInstruction32bit();
            // - BytesAreDirectRelativeJmpInstruction64bit();
            // would validate the same bytes for relative "jmp 0xAddress" instructions as Capstone does.
            // However, that's not always the case since our methods are a bit permissive with the prefix bytes.
            // Example:
            // "0xF0 0xEB one_byte" and "0xF0 0xE9 four_bytes"
            // would correspond to "lock jmp 0xAddress" instructions, which are illegal
            // since the "lock" prefix is not allowed for relative "jmp" instructions.
            // But our methods identify those bytes as valid instructions, while Capstone doesn't.
            continue;
        }

        RegisterInfo *jmpRegInfoPtr = NULL;
        if (VirtualMemoryInstructions::computeRegisterInfo) {
            jmpRegInfoPtr = &this->regInfoForSegment[jmpFirstIndex];
        }

        // Compute the address of the jmp instruction.
        addressType jmpVMAddress = segm.startVirtualAddress + jmpFirstIndex;

        // Add the jmp instruction into the trie.
        auto currNode = this->instructionTrie.addInstruction(prevNode, jmpInstruction, jmpVMAddress, jmpRegInfoPtr);

        // Recurse and try to extend the instruction sequence further.
        const int currInstrSeqLength = prevInstrSeqLength + 1;
        this->extendInstructionSequenceAndAddToTrie(segm,
                                                    currNode,
                                                    jmpFirstIndex,
                                                    jmpVMAddress,
                                                    currInstrSeqLength);
    }
}

void ROP::VirtualMemoryInstructions::extendInstructionSequenceAndAddToTrie(
    const VirtualMemorySegmentBytes& segm,
    InsSeqTrie::Node *prevNode,
    const int prevFirstIndex,
    const addressType prevVMAddress,
    const int prevInstrSeqLength
) {
    this->extendInstructionSequenceThroughDirectlyPrecedingInstructions(segm,
                                                                        prevNode,
                                                                        prevFirstIndex,
                                                                        prevVMAddress,
                                                                        prevInstrSeqLength);

    if (VirtualMemoryInstructions::SearchForSequencesWithDirectRelativeJumpsInTheMiddle) {
        this->extendInstructionSequenceThroughRelativeJmpInstructions(segm,
                                                                      prevNode,
                                                                      prevFirstIndex,
                                                                      prevVMAddress,
                                                                      prevInstrSeqLength);
    }
}

void ROP::VirtualMemoryInstructions::buildInstructionTrie() {
    for (const VirtualMemorySegmentBytes& segm : this->vmBytes.getExecutableSegments()) {
        if (VirtualMemoryInstructions::SearchForSequencesWithDirectRelativeJumpsInTheMiddle) {
            this->buildRelativeJmpMap(segm);
        }

        for (int rightIdx = (int)segm.bytes.size()-1; rightIdx >= 0; --rightIdx) {
            // This is just for making the first preceding instruction
            // think it needs to end at (prevFirstIndex - 1), i.e. at rightIdx.
            const int prevFirstIndex = rightIdx + 1;

            this->extendInstructionSequenceAndAddToTrie(segm,
                                                        this->instructionTrie.root,
                                                        prevFirstIndex,
                                                        0xDeadBeef, // doesn't matter for first call
                                                        0 // no previous instructions
                                                        );
        }

        this->disassembledSegment.clear();
        this->regInfoForSegment.clear();
        this->jmpIndexesForAddress.clear();
    }

    // Pass this output filter to the trie.
    bool ign = VirtualMemoryInstructions::IgnoreOutputSequencesThatStartWithDirectRelativeJumps;
    this->instructionTrie.ignoreOutputSequencesThatStartWithDirectRelativeJumps = ign;
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(int processPid)
: vmBytes(processPid), ic(this->vmBytes.getProcessArchSize()) {
    this->archBitSize = this->vmBytes.getProcessArchSize();
    this->buildInstructionTrie();
}

ROP::VirtualMemoryInstructions::VirtualMemoryInstructions(const std::vector<std::string> execPaths,
                                                          const std::vector<addressType> baseAddresses)
: vmBytes(execPaths, baseAddresses), ic(this->vmBytes.getProcessArchSize()) {
    this->archBitSize = this->vmBytes.getProcessArchSize();
    this->buildInstructionTrie();
}

const ROP::VirtualMemoryBytes&
ROP::VirtualMemoryInstructions::getVirtualMemoryBytes() const {
    return this->vmBytes;
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
