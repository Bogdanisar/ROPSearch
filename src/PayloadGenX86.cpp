#include "PayloadGenX86.hpp"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <sstream>

#include "common/utils.hpp"


void ROP::PayloadGenX86::preconfigureVMInstructionsObject() {
    VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = 10;
    VirtualMemoryInstructions::SearchForSequencesWithDirectRelativeJumpsInTheMiddle = true;
    VirtualMemoryInstructions::IgnoreOutputSequencesThatStartWithDirectRelativeJumps = true;
    VirtualMemoryInstructions::innerAssemblySyntax = ROP::AssemblySyntax::Intel;
    VirtualMemoryInstructions::computeRegisterInfo = true;
}

ROP::PayloadGenX86::PayloadGenX86(int processPid) {
    this->preconfigureVMInstructionsObject();
    this->vmInstructionsObject = VirtualMemoryInstructions(processPid);
}

ROP::PayloadGenX86::PayloadGenX86(const std::vector<std::string> execPaths,
                                  const std::vector<addressType> baseAddresses) {
    this->preconfigureVMInstructionsObject();
    this->vmInstructionsObject = VirtualMemoryInstructions(execPaths, baseAddresses);
}


void ROP::PayloadGenX86::loadTheSyscallArgNumberMap() {
    if (this->processArchSize == BitSizeClass::BIT64) {
        this->syscallArgNumberToRegKey.push_back(X86_REG_RAX);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RDI);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RSI);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RDX);
        this->syscallArgNumberToRegKey.push_back(X86_REG_R10);
        this->syscallArgNumberToRegKey.push_back(X86_REG_R8);
        this->syscallArgNumberToRegKey.push_back(X86_REG_R9);
    }
    else {
        assert(this->processArchSize == BitSizeClass::BIT32);

        // Register keys are always represented by 64bit enums.
        this->syscallArgNumberToRegKey.push_back(X86_REG_RAX);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RBX);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RCX);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RDX);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RSI);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RDI);
        this->syscallArgNumberToRegKey.push_back(X86_REG_RBP);
    }
}

void ROP::PayloadGenX86::loadTheRegisterMaps() {
    BitSizeClass archSize = this->processArchSize;

    // Compute values for `this->usableRegKeys` member.
    this->usableRegKeys.insert(X86_REG_RAX);
    this->usableRegKeys.insert(X86_REG_RBX);
    this->usableRegKeys.insert(X86_REG_RCX);
    this->usableRegKeys.insert(X86_REG_RDX);
    this->usableRegKeys.insert(X86_REG_RSI);
    this->usableRegKeys.insert(X86_REG_RDI);
    this->usableRegKeys.insert(X86_REG_RBP);
    if (archSize == BitSizeClass::BIT64) {
        this->usableRegKeys.insert(X86_REG_R8);
        this->usableRegKeys.insert(X86_REG_R9);
        this->usableRegKeys.insert(X86_REG_R10);
        this->usableRegKeys.insert(X86_REG_R11);
        this->usableRegKeys.insert(X86_REG_R12);
        this->usableRegKeys.insert(X86_REG_R13);
        this->usableRegKeys.insert(X86_REG_R14);
        this->usableRegKeys.insert(X86_REG_R15);
    }

    // Compute values for `this->regKeyToMainReg` member.
    if (archSize == BitSizeClass::BIT64) {
        std::vector<x86_reg> regIdentifiers = {
            X86_REG_RAX,
            X86_REG_RBX,
            X86_REG_RCX,
            X86_REG_RDX,
            X86_REG_RSI,
            X86_REG_RDI,
            X86_REG_RBP,
            X86_REG_RSP,
            X86_REG_RIP,
            X86_REG_R8,
            X86_REG_R9,
            X86_REG_R10,
            X86_REG_R11,
            X86_REG_R12,
            X86_REG_R13,
            X86_REG_R14,
            X86_REG_R15,
        };

        for (x86_reg currReg : regIdentifiers) {
            this->regKeyToMainReg[currReg] = currReg;
        }
    }
    else {
        assert(archSize == BitSizeClass::BIT32);
        this->regKeyToMainReg[X86_REG_RAX] = X86_REG_EAX;
        this->regKeyToMainReg[X86_REG_RBX] = X86_REG_EBX;
        this->regKeyToMainReg[X86_REG_RCX] = X86_REG_ECX;
        this->regKeyToMainReg[X86_REG_RDX] = X86_REG_EDX;
        this->regKeyToMainReg[X86_REG_RSI] = X86_REG_ESI;
        this->regKeyToMainReg[X86_REG_RDI] = X86_REG_EDI;
        this->regKeyToMainReg[X86_REG_RBP] = X86_REG_EBP;
        this->regKeyToMainReg[X86_REG_RSP] = X86_REG_ESP;
        this->regKeyToMainReg[X86_REG_RIP] = X86_REG_EIP;
    }

    // Compute values for `this->regKeyToPartialRegs` member.
    std::vector<std::vector<x86_reg>> partialRegisterGroups = {
        { X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AH, X86_REG_AL },
        { X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BH, X86_REG_BL },
        { X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CH, X86_REG_CL },
        { X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DH, X86_REG_DL },
        { X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL },
        { X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL },
        { X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL },
        { X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL },
        { X86_REG_RIP, X86_REG_EIP },
        { X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_R8B },
        { X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_R9B },
        { X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B },
        { X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B },
        { X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B },
        { X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B },
        { X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B },
        { X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B },
    };
    for (std::vector<x86_reg> regGroup : partialRegisterGroups) {
        x86_reg leader = regGroup[0];

        if (archSize == BitSizeClass::BIT64) {
            this->regKeyToPartialRegs[leader] = std::set<x86_reg>(regGroup.begin(), regGroup.end());
        }
        else {
            assert(archSize == BitSizeClass::BIT32);
            if (leader == X86_REG_R8) {
                break;
            }

            regGroup.erase(regGroup.begin());
            this->regKeyToPartialRegs[leader] = std::set<x86_reg>(regGroup.begin(), regGroup.end());
        }
    }

    // Compute values for `this->regKeyToEndingPartialRegs` member.
    for (const auto& it : this->regKeyToPartialRegs) {
        x86_reg leader = it.first;
        std::set<x86_reg> regGroup = it.second;

        regGroup.erase(X86_REG_AH);
        regGroup.erase(X86_REG_BH);
        regGroup.erase(X86_REG_CH);
        regGroup.erase(X86_REG_DH);

        this->regKeyToEndingPartialRegs[leader] = regGroup;
    }
}

void ROP::PayloadGenX86::loadTheStackPointerInstructionToOffsetMap() {
    std::map<unsigned, std::vector<std::string>> offsetToRegs;
    offsetToRegs[8] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", // "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    offsetToRegs[4] = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", // "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    };
    offsetToRegs[2] = {
        "ax", "bx", "cx", "dx", "si", "di", "bp", // "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    };

    // I don't think "pop al" etc. is possible.
    // offsetToRegs[1] = {
    //     "ah", "bh", "ch", "dh",
    //     "al", "bl", "cl", "dl", "sil", "dil", "bpl", // "spl",
    //     "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    // };

    for (const auto& it : offsetToRegs) {
        unsigned offset = it.first;
        const std::vector<std::string>& regStringList = it.second;
        for (const std::string& regString : regStringList) {
            std::string popInstruction = "pop " + regString;
            this->stackPointerIncreaseInstructionToOffset[popInstruction] = offset;
        }
    }

    this->stackPointerIncreaseInstructionToOffset["inc rsp"] = 1;
    this->stackPointerIncreaseInstructionToOffset["inc esp"] = 1;
    this->stackPointerIncreaseInstructionToOffset["inc sp"] = 1;
    this->stackPointerIncreaseInstructionToOffset["inc spl"] = 1;

    unsigned maxOffset = this->numAcceptablePaddingBytesForOneInstruction;
    char offsetBuffer[100];
    for (unsigned offset = 0; offset <= maxOffset; ++offset) {
        for (std::string regString : {"rsp", "esp", "sp", "spl"}) {
            memset(offsetBuffer, 0, sizeof(offsetBuffer));
            sprintf(offsetBuffer, "%x", offset);

            std::string instruction = "add " + regString + ", 0x" + offsetBuffer;
            this->stackPointerIncreaseInstructionToOffset[instruction] = offset;
        }
    }
}

void ROP::PayloadGenX86::computeRelevantSequenceIndexes() {
    assertMessage(this->instrSeqs.size() == this->regInfoSeqs.size(), "Inner logic error.");

    // Generate relevant indexes;
    std::set<std::string> concatenatedInstrSeqStrings;
    for (unsigned idx = 0; idx < this->instrSeqs.size(); ++idx) {

        if (this->forbidNullBytesInPayload) {
            // Check if there are any NULL bytes
            // in the virtual memory address of this instruction sequence;
            // If yes, ignore this sequence;

            const addressType& addr = this->instrSeqs[idx].first;
            bool addressHasNullBytes = (GetNumNullBytesOfRegisterSizedConstant(this->processArchSize, addr) > 0);
            if (addressHasNullBytes) {
                // Ignore this sequence
                continue;
            }
        }

        if (this->ignoreDuplicateInstructionSequenceResults) {
            // Check if the current instruction has been found before.

            const std::vector<std::string>& insSeq = this->instrSeqs[idx].second;
            std::string seqString = InstructionConverter::concatenateInstructionsAsm(insSeq);
            if (concatenatedInstrSeqStrings.count(seqString) != 0) {
                // The current sequence is a duplicate. Ignore it.
                continue;
            }

            // Remember the current sequence string.
            concatenatedInstrSeqStrings.insert(seqString);
        }

        this->sequenceIndexList.push_back(idx);
    }

    // Sort the sequences by the length of the instruction sequence, increasingly.
    auto comparator = [&](unsigned idxA, unsigned idxB) {
        return (this->instrSeqs[idxA].second.size() < this->instrSeqs[idxB].second.size());
    };
    sort(this->sequenceIndexList.begin(), this->sequenceIndexList.end(), comparator);

    // Compute `this->firstInstrToSequenceIndexes` member.
    for (unsigned seqIndex : this->sequenceIndexList) {
        const std::vector<std::string>& instrSequence = this->instrSeqs[seqIndex].second;
        const std::string& firstInstr = instrSequence[0];
        this->firstInstrToSequenceIndexes[firstInstr].push_back(seqIndex);
    }
}

void ROP::PayloadGenX86::configureGenerator() {
    if (this->numAcceptablePaddingBytesForOneInstruction > 400) {
        this->numAcceptablePaddingBytesForOneInstruction = 400;
    }

    this->processArchSize = this->vmInstructionsObject.getVirtualMemoryBytes().getProcessArchSize();
    this->registerByteSize = (this->processArchSize == BitSizeClass::BIT64) ? 8 : 4;
    this->loadTheSyscallArgNumberMap();
    this->loadTheRegisterMaps();
    this->loadTheStackPointerInstructionToOffsetMap();

    this->instrSeqs = this->vmInstructionsObject.getInstructionSequences(&this->regInfoSeqs);
    this->computeRelevantSequenceIndexes();
}


void ROP::PayloadGenX86::addLineToPythonScript(const std::string& line) {
    std::string prefix = "";
    prefix.insert(0, this->currLineIndent * 4, ' ');
    if (this->currScriptLineIsComment) {
        prefix.append("# ");
    }

    this->pythonScript.push_back(prefix + line);
}

void ROP::PayloadGenX86::appendInstructionSequenceToPayload(unsigned sequenceIndex) {
    const auto& currentPair = this->instrSeqs[sequenceIndex];
    addressType address = currentPair.first;
    const std::vector<std::string>& instrSequence = currentPair.second;
    std::string sequenceString = InstructionConverter::concatenateInstructionsAsm(instrSequence);

    byteSequence addressBytes;
    if (this->processArchSize == BitSizeClass::BIT64) {
        addressBytes = BytesOfInteger((uint64_t)address);
    }
    else {
        assert(this->processArchSize == BitSizeClass::BIT32);
        addressBytes = BytesOfInteger((uint32_t)address);
    }

    if (!this->currScriptLineIsComment) {
        this->payloadBytes.insert(this->payloadBytes.end(), addressBytes.begin(), addressBytes.end());
    }

    std::ostringstream ss;

    // Add assignment statement for the bytes.
    ss << "payload += b'";
    ss << std::hex << std::uppercase << std::setfill('0');
    for (ROP::byte currByte : addressBytes) {
        ss << "\\x" << std::setw(2) << (unsigned)currByte;
    }
    ss << "' ";

    // Add "# 0xAddress: Instruction Sequence" comment.
    ss << "# 0x" << IntToHex(address, 2 * this->registerByteSize, false);
    ss << ": " << sequenceString;

    this->addLineToPythonScript(ss.str());
}

void ROP::PayloadGenX86::appendBytesOfRegisterSizedConstantToPayload(const uint64_t cValue) {
    byteSequence bytes;
    if (this->processArchSize == BitSizeClass::BIT64) {
        bytes = BytesOfInteger((uint64_t)cValue);
    }
    else {
        assert(this->processArchSize == BitSizeClass::BIT32);
        bytes = BytesOfInteger((uint32_t)cValue);
    }

    if (!this->currScriptLineIsComment) {
        this->payloadBytes.insert(this->payloadBytes.end(), bytes.begin(), bytes.end());
    }

    // Add "payload += b'...' # Value: 0x..." line.
    std::ostringstream ss;
    ss << "payload += b'";
    ss << std::hex << std::uppercase << std::setfill('0');
    for (ROP::byte currByte : bytes) {
        ss << "\\x" << std::setw(2) << (unsigned)currByte;
    }
    ss << "' # Value: 0x" << IntToHex(cValue, 2 * this->registerByteSize, true);
    this->addLineToPythonScript(ss.str());
}

void ROP::PayloadGenX86::appendPaddingBytesToPayload(const unsigned numPaddingBytes) {
    if (numPaddingBytes == 0) {
        return;
    }

    if (!this->currScriptLineIsComment) {
        this->payloadBytes.insert(this->payloadBytes.end(), numPaddingBytes, 0xFF);
    }

    std::ostringstream ss;
    ss << "payload += b'0xFF' * " << numPaddingBytes;
    this->addLineToPythonScript(ss.str());
}

bool ROP::PayloadGenX86::tryAppendOperationsAndRevertOnFailure(const std::function<bool(void)>& cb) {
    unsigned prevPayloadBytesSize = this->payloadBytes.size();
    unsigned prevPayloadScriptSize = this->pythonScript.size();

    bool success = cb();
    if (!success) {
        this->payloadBytes.resize(prevPayloadBytesSize);
        this->pythonScript.resize(prevPayloadScriptSize);
    }

    return success;
}


bool ROP::PayloadGenX86::instructionIsWhitelistedInSequence(const std::string& instruction,
                                                            const RegisterInfo& regInfo) {
    UNUSED(regInfo);
    auto instrSize = instruction.size();

    // Check if this is a direct relative jmp instruction (i.e. "jmp 0xAddress -->").
    if (instrSize >= 3) {
        bool hasRelJmpPrefix = (instruction.compare(0, 3, "jmp") == 0);
        bool hasRelJmpSuffix = (instruction.compare(instrSize - 3, 3, "-->") == 0);
        if (hasRelJmpPrefix && hasRelJmpSuffix) {
            return true;
        }
    }

    return false;
}

bool ROP::PayloadGenX86::instructionIsBlacklistedInSequence(const std::string& instruction,
                                                            const RegisterInfo& regInfo) {
    UNUSED(regInfo);

    std::vector<std::string> badPrefixList = {
        "enter ", // Wrong Capstone register info. E.g. "enter 0x280f, -0x3f".
        "j", // For (conditional) jumps. The relative jumps are whitelisted beforehand.
    };

    for (const std::string& badPrefix : badPrefixList) {
        bool hasPrefix = (instruction.compare(0, badPrefix.size(), badPrefix) == 0);
        if (hasPrefix) {
            return true;
        }
    }

    return false;
}

int ROP::PayloadGenX86::instructionIsSafeStackPointerIncrease(const std::string& instruction,
                                                              const RegisterInfo& regInfo,
                                                              std::set<x86_reg> forbiddenRegisters) {
    const auto& mapEnd = this->stackPointerIncreaseInstructionToOffset.end();
    if (this->stackPointerIncreaseInstructionToOffset.find(instruction) == mapEnd) {
        return -1;
    }

    // So this is a valid pop instruction.
    // We just need to check if it pops any forbidden register.

    // Remove stack pointer registers from the forbidden registers set,
    // since any "pop reg" instruction will change the stack pointer.
    for (x86_reg regId : this->regKeyToPartialRegs[X86_REG_RSP]) {
        forbiddenRegisters.erase(regId);
    }

    for (x86_reg forbiddenRegId : forbiddenRegisters) {
        bool writesToRegister = regInfo.wRegs.test(forbiddenRegId);
        if (writesToRegister) {
            return -1;
        }
    }

    int offset = (int)this->stackPointerIncreaseInstructionToOffset[instruction];
    return offset;
}

int ROP::PayloadGenX86::checkInstructionIsRetAndGetImmediateValue(const std::string& instruction,
                                                                  const RegisterInfo& regInfo) {
    UNUSED(regInfo);

    // Check if this is a "ret" instruction.
    if (instruction == "ret") {
        return 0;
    }

    // Check if this is a "ret imm16" instruction.
    unsigned immediateValue = 0;
    int bytesRead = -1;
    sscanf(instruction.c_str(), "ret 0x%x%n", &immediateValue, &bytesRead);
    return (bytesRead == (int)instruction.size()) ? (int)immediateValue : -1;
}

unsigned ROP::PayloadGenX86::getNumberOfVariantsToOutputForThisStep(unsigned numFoundVariants) {
    if (this->numVariantsToOutputForEachStep == 0) {
        return numFoundVariants;
    }

    return std::min(this->numVariantsToOutputForEachStep, numFoundVariants);
}


std::vector<ROP::PayloadGenX86::SequenceLookupResult>
ROP::PayloadGenX86::searchForSequenceStartingWithInstruction(const std::string& targetInstruction,
                                                             const std::set<x86_reg>& forbiddenRegisterKeys) {
    // Take the given list of register keys, which are just representatives for their partial register set,
    // And append the full partial register set of those registers (+ RIP and RSP)
    // to this expanded set of forbidden registers;
    std::set<x86_reg> expandedForbiddenRegs;
    for (const x86_reg regSetLeader : forbiddenRegisterKeys) {
        const std::set<x86_reg>& partialRegSet = this->regKeyToPartialRegs[regSetLeader];
        expandedForbiddenRegs.insert(partialRegSet.begin(), partialRegSet.end());
    }
    for (const x86_reg regSetLeader : {X86_REG_RIP, X86_REG_RSP}) {
        const std::set<x86_reg>& partialRegSet = this->regKeyToPartialRegs[regSetLeader];
        expandedForbiddenRegs.insert(partialRegSet.begin(), partialRegSet.end());
    }

    std::vector<SequenceLookupResult> results;
    for (unsigned sequenceIndex : this->firstInstrToSequenceIndexes[targetInstruction]) {
        auto addressAndSequencePair = this->instrSeqs[sequenceIndex];
        addressType address = addressAndSequencePair.first;
        const std::vector<std::string>& currInstrSequence = addressAndSequencePair.second;
        const std::vector<RegisterInfo>& currRegInfoSequence = this->regInfoSeqs[sequenceIndex];
        UNUSED(address);

        // See if the first instruction in the sequence is the one that we want.
        assert(currInstrSequence.size() > 0);
        assert(currInstrSequence[0] == targetInstruction);

        // See if the other instructions in the sequence, ignoring the last one, don't break anything important.
        bool sequenceIsGood = true;
        unsigned totalNumPaddingNeeded = 0;
        for (unsigned instructionIndex = 1; instructionIndex < currInstrSequence.size() - 1; ++instructionIndex) {
            const std::string& currentInstruction = currInstrSequence[instructionIndex];
            const RegisterInfo& currentRegInfo = currRegInfoSequence[instructionIndex];

            if (this->instructionIsWhitelistedInSequence(currentInstruction, currentRegInfo)) {
                // The current instruction is fine.
                continue;
            }

            // Writing to memory could overwrite something important.
            // Or we might not have access to that address, which would cause a segmentation fault.
            if (currentRegInfo.writesMemoryOperand) {
                sequenceIsGood = false;
                break;
            }

            // Reading memory isn't by itself a bad side-effect in principle, but we might read from an address
            // for which we don't have permissions, which would cause a segmentation fault.
            if (currentRegInfo.readsMemoryOperand) {
                sequenceIsGood = false;
                break;
            }

            int rspOffset = this->instructionIsSafeStackPointerIncrease(currentInstruction,
                                                                        currentRegInfo,
                                                                        expandedForbiddenRegs);
            bool isSafeStackPointerIncreaseInstruction = (rspOffset != -1);
            if (isSafeStackPointerIncreaseInstruction) {
                // The current instruction is something like "pop rbx" or "add esp, 0x20".
                // We checked and it doesn't write to any forbidden registers, so it's fine;
                totalNumPaddingNeeded += rspOffset;
                continue;
            }

            // Check if the instruction writes to any of the forbidden registers.
            bool instructionWritesToForbiddenRegisters = false;
            for (x86_reg forbiddenRegId : expandedForbiddenRegs) {
                bool writesToRegister = currentRegInfo.wRegs.test(forbiddenRegId);
                if (writesToRegister) {
                    instructionWritesToForbiddenRegisters = true;
                    break;
                }
            }
            if (instructionWritesToForbiddenRegisters) {
                sequenceIsGood = false;
                break;
            }

            if (this->instructionIsBlacklistedInSequence(currentInstruction, currentRegInfo)) {
                // The current instruction is bad. We can't accept this sequence.
                sequenceIsGood = false;
                break;
            }
        }

        // Check if the last instruction is ok.
        int imm = this->checkInstructionIsRetAndGetImmediateValue(currInstrSequence.back(),
                                                                  currRegInfoSequence.back());
        bool lastInstructionIsRet = (imm != -1);
        if (lastInstructionIsRet && imm <= (int)this->numAcceptablePaddingBytesForOneInstruction) {
            // All good.
            totalNumPaddingNeeded += imm;
        }
        else {
            // Bad final instruction.
            sequenceIsGood = false;
        }

        if (sequenceIsGood) {
            SequenceLookupResult currentResult;
            currentResult.index = sequenceIndex;
            currentResult.numNeededPaddingBytes = totalNumPaddingNeeded;
            results.push_back(currentResult);
        }
    }

    return results;
}

bool
ROP::PayloadGenX86::appendGadgetStartingWithInstruction(const std::vector<std::string>& targetFirstInstructionList,
                                                        std::set<x86_reg> forbiddenRegisterKeys,
                                                        const std::function<void(const std::string&)>& appendLinesAfterAddressBytesCb) {
    std::vector<SequenceLookupResult> allSeqResults;

    for (const std::string& targetFirstInstr : targetFirstInstructionList) {
        std::vector<SequenceLookupResult> currSeqResults;
        currSeqResults = this->searchForSequenceStartingWithInstruction(targetFirstInstr,
                                                                        forbiddenRegisterKeys);
        if (currSeqResults.size() != 0) {
            LogDebug("Found a useful instruction sequence starting with \"%s\".", targetFirstInstr.c_str());
            allSeqResults.insert(allSeqResults.end(), currSeqResults.begin(), currSeqResults.end());
        }
    }

    if (allSeqResults.size() == 0) {
        std::ostringstream ss;
        ss << "Can't find a useful instruction sequence starting with any of: ";
        for (const std::string& targetFirstInstr : targetFirstInstructionList) {
            ss << '"' << targetFirstInstr << '"' << ", ";
        }
        LogDebug("%s", ss.str().c_str());

        return false;
    }

    this->addLineToPythonScript("if True:");
    this->currLineIndent++;

    unsigned numToOutput = this->getNumberOfVariantsToOutputForThisStep(allSeqResults.size());
    for (unsigned idx = 0; idx < numToOutput; ++idx) {
        const std::vector<std::string>& sequence = this->instrSeqs[allSeqResults[idx].index].second;
        const std::string& firstInstruction = sequence[0];

        this->currScriptLineIsComment = (idx != 0);
        this->appendInstructionSequenceToPayload(allSeqResults[idx].index);
        appendLinesAfterAddressBytesCb(firstInstruction);
        this->appendPaddingBytesToPayload(allSeqResults[idx].numNeededPaddingBytes);
        this->currScriptLineIsComment = false;

        this->addLineToPythonScript(""); // New line.
    }

    this->currLineIndent--;

    return true;
}


bool ROP::PayloadGenX86::appendGadgetForCopyOrExchangeRegisters(x86_reg destRegKey,
                                                                x86_reg srcRegKey,
                                                                std::set<x86_reg> forbiddenRegisterKeys,
                                                                int numAllowedIntermediates,
                                                                bool isParentCall) {
    std::string destStr = InstructionConverter::convertCapstoneRegIdToShortStringLowercase(this->regKeyToMainReg[destRegKey]);
    std::string srcStr = InstructionConverter::convertCapstoneRegIdToShortStringLowercase(this->regKeyToMainReg[srcRegKey]);
    LogDebug("Trying to do: (%s = %s).", destStr.c_str(), srcStr.c_str());

    assertMessage(forbiddenRegisterKeys.count(destRegKey) == 0, "The destination register has to be changed...");
    bool success;

    success = this->tryAppendOperationsAndRevertOnFailure([&] {
        std::vector<std::string> targetFirstInstructionList = {
            "mov " + destStr + ", " + srcStr,
            "lea " + destStr + ", [" + srcStr + "]",
        };

        if (forbiddenRegisterKeys.count(srcRegKey) == 0) {
            // It's fine to change the value of the source register.
            targetFirstInstructionList.push_back("xchg " + destStr + ", " + srcStr);
            targetFirstInstructionList.push_back("xchg " + srcStr + ", " + destStr);
        }

        this->addLineToPythonScript("# " + destStr + " = " + srcStr);
        return this->appendGadgetStartingWithInstruction(targetFirstInstructionList,
                                                         AddSets(forbiddenRegisterKeys, {destRegKey}),
                                                         [](const std::string&){});
    });
    if (success) { return true; }

    // Try with some intermediate registers.
    if (numAllowedIntermediates != 0) {
        for (x86_reg midRegKey : this->usableRegKeys) {
            if (midRegKey == destRegKey || midRegKey == srcRegKey) {
                continue;
            }
            if (forbiddenRegisterKeys.count(midRegKey) != 0) {
                continue;
            }

            success = this->tryAppendOperationsAndRevertOnFailure([&] {
                if (isParentCall) {
                    this->addLineToPythonScript("# " + destStr + " = " + srcStr + " (with intermediates).");
                    this->addLineToPythonScript("if True:");
                    this->currLineIndent++;
                }

                bool ok = true;
                ok = ok && this->appendGadgetForCopyOrExchangeRegisters(midRegKey,
                                                                        srcRegKey,
                                                                        forbiddenRegisterKeys,
                                                                        0,
                                                                        false);
                ok = ok && this->appendGadgetForCopyOrExchangeRegisters(destRegKey,
                                                                        midRegKey,
                                                                        forbiddenRegisterKeys,
                                                                        numAllowedIntermediates - 1,
                                                                        false);

                if (isParentCall) {
                    this->currLineIndent--;
                }

                return ok;
            });
            if (success) { return true; }
        }
    }

    return false;
}

bool ROP::PayloadGenX86::appendGadgetForAssignValueToRegister(x86_reg destRegKey,
                                                              uint64_t cValue,
                                                              std::set<x86_reg> forbiddenRegisterKeys,
                                                              int numAllowedIntermediates,
                                                              bool isParentCall) {
    if (this->processArchSize == BitSizeClass::BIT32) { cValue = (uint32_t)cValue; }
    std::string prettyHexValue = IntToHex(cValue, 2 * this->registerByteSize, true);

    std::string destRegStr = InstructionConverter::convertCapstoneRegIdToShortStringLowercase(this->regKeyToMainReg[destRegKey]);
    LogDebug("Trying to do: (%s = %s).", destRegStr.c_str(), prettyHexValue.c_str());

    assertMessage(forbiddenRegisterKeys.count(destRegKey) == 0, "The destination register has to be changed...");
    bool success;

    success = this->tryAppendOperationsAndRevertOnFailure([&] {
        this->addLineToPythonScript("# " + destRegStr + " = 0x" + prettyHexValue);

        std::string shortHexValue;
        if (this->processArchSize == BitSizeClass::BIT64) {
            shortHexValue = IntToHex((uint64_t)cValue, 0, false);
        }
        else {
            assert(this->processArchSize == BitSizeClass::BIT32);
            shortHexValue = IntToHex((uint32_t)cValue, 0, false);
        }

        std::vector<std::string> targetFirstInstructionList;
        if (cValue == 0) {
            targetFirstInstructionList.push_back("mov " + destRegStr + ", 0"); // This seems to be the syntax.
            targetFirstInstructionList.push_back("mov " + destRegStr + ", 0x0");
            targetFirstInstructionList.push_back("and " + destRegStr + ", 0"); // This seems to be the syntax.
            targetFirstInstructionList.push_back("and " + destRegStr + ", 0x0");
            targetFirstInstructionList.push_back("xor " + destRegStr + ", " + destRegStr);
            targetFirstInstructionList.push_back("sub " + destRegStr + ", " + destRegStr);
        }
        else {
            targetFirstInstructionList.push_back("mov " + destRegStr + ", 0x" + shortHexValue);
        }

        bool nullBytesAreAllowed = !this->forbidNullBytesInPayload;
        bool valueIsNullFree = (GetNumNullBytesOfRegisterSizedConstant(this->processArchSize, cValue) == 0);
        if (nullBytesAreAllowed || valueIsNullFree) {
            targetFirstInstructionList.push_back("pop " + destRegStr);
        }

        return this->appendGadgetStartingWithInstruction(targetFirstInstructionList,
                                                         AddSets(forbiddenRegisterKeys, {destRegKey}),
                                                         [&](const std::string& firstInstr) {
            if (firstInstr.compare(0, 3, "pop") == 0) {
                this->appendBytesOfRegisterSizedConstantToPayload(cValue);
            }
        });
    });
    if (success) { return true; }

    // Try with some intermediate registers.
    if (numAllowedIntermediates != 0) {
        for (x86_reg midRegKey : this->usableRegKeys) {
            if (midRegKey == destRegKey) {
                continue;
            }
            if (forbiddenRegisterKeys.count(midRegKey) != 0) {
                continue;
            }

            success = this->tryAppendOperationsAndRevertOnFailure([&] {
                if (isParentCall) {
                    this->addLineToPythonScript("# " + destRegStr + " = 0x" + prettyHexValue + " (with intermediates)");
                    this->addLineToPythonScript("if True:");
                    this->currLineIndent++;
                }

                bool ok = true;
                ok = ok && this->appendGadgetForAssignValueToRegister(midRegKey,
                                                                      cValue,
                                                                      forbiddenRegisterKeys,
                                                                      0,
                                                                      false);
                ok = ok && this->appendGadgetForCopyOrExchangeRegisters(destRegKey,
                                                                        midRegKey,
                                                                        forbiddenRegisterKeys,
                                                                        numAllowedIntermediates - 1,
                                                                        false);

                if (isParentCall) {
                    this->currLineIndent--;
                }

                return ok;
            });
            if (success) { return true; }
        }
    }

    return false;
}


bool ROP::PayloadGenX86::appendROPChainForShellCodeWithPathNullNull() {
    // Find "/bin/sh" in memory.
    addressType binShAddress = 0;
    std::vector<addressType> matchedAddressList;
    matchedAddressList = this->vmInstructionsObject.getVirtualMemoryBytes().matchStringInVirtualMemory("/bin/sh");
    for (addressType addr : matchedAddressList) {
        bool nullBytesAreAllowed = !this->forbidNullBytesInPayload;
        bool valueIsNullFree = (GetNumNullBytesOfRegisterSizedConstant(this->processArchSize, addr) == 0);
        if (nullBytesAreAllowed || valueIsNullFree) {
            binShAddress = addr;
        }
    }

    if (binShAddress == 0) {
        exitError("Can't find good address for \"/bin/sh\" in virtual memory...");
    }

    // Putting the right value into each argument takes some gadget work.
    using argWorkType = std::function<bool(const std::set<x86_reg>&)>;
    std::vector<argWorkType> argWorkClosure;

    // Argument for system call id.
    argWorkClosure.push_back([&](const std::set<x86_reg>& forbiddenRegisterKeys) {
        x86_reg regKey = this->syscallArgNumberToRegKey[0];
        uint64_t syscallId = (this->processArchSize == BitSizeClass::BIT64) ? 59 : 11;
        return this->appendGadgetForAssignValueToRegister(regKey, syscallId, forbiddenRegisterKeys);
    });

    // First argument. Reg = "/bin/sh";
    argWorkClosure.push_back([&](const std::set<x86_reg>& forbiddenRegisterKeys) {
        x86_reg regKey = this->syscallArgNumberToRegKey[1];
        return this->appendGadgetForAssignValueToRegister(regKey, binShAddress, forbiddenRegisterKeys);
    });

    // Second argument. Reg = 0 (NULL);
    argWorkClosure.push_back([&](const std::set<x86_reg>& forbiddenRegisterKeys) {
        x86_reg regKey = this->syscallArgNumberToRegKey[2];
        return this->appendGadgetForAssignValueToRegister(regKey, 0, forbiddenRegisterKeys);
    });

    // Third argument. Reg = 0 (NULL);
    argWorkClosure.push_back([&](const std::set<x86_reg>& forbiddenRegisterKeys) {
        x86_reg regKey = this->syscallArgNumberToRegKey[3];
        return this->appendGadgetForAssignValueToRegister(regKey, 0, forbiddenRegisterKeys);
    });

    // Try assigning the necessary values to the arguments in all possible orders.
    std::vector<unsigned> argIndexes = {0, 1, 2, 3};
    do {
        LogDebug("Checking shell rop-chain generation for arg indexes: (%u, %u, %u, %u)",
                 argIndexes[0], argIndexes[1], argIndexes[2], argIndexes[3]);

        bool success;
        success = this->tryAppendOperationsAndRevertOnFailure([&] {
            bool ok = true;

            std::set<x86_reg> forbiddenRegKeys = {};
            for (unsigned currArgumentIndex : argIndexes) {
                // Try to perform the work for the current argument.
                x86_reg currRegKey = this->syscallArgNumberToRegKey[currArgumentIndex];
                ok = ok && argWorkClosure[currArgumentIndex](forbiddenRegKeys);

                // Remember the current register as forbidden for the next gadgets.
                forbiddenRegKeys.insert(currRegKey);
            }

            return ok;
        });
        if (success) { return true; }
    } while (std::next_permutation(argIndexes.begin(), argIndexes.end()));

    return false;
}


static inline std::string GetPathToFileInSameParentDirectory(const std::string& filename) {
    // Get the path to the running executable.
    std::filesystem::path execPath = GetAbsPathToProcExecutable();

    // Remove the file path component at the end of the path.
    std::filesystem::path parentDirPath = execPath.remove_filename();

    // Append the filename component to the path.
    std::filesystem::path filePath = parentDirPath / filename;
    const std::string& filePathString = filePath.string();

    return filePathString;
}

void ROP::PayloadGenX86::writePayloadToFile(const std::string& filename) {
    const std::string& filePathString = GetPathToFileInSameParentDirectory(filename);

    // Open the file for writing bytes.
    std::ofstream fout(filePathString, std::ios::binary);
    if (fout.fail()) {
        exitError("Can't open file (%s) for writing the payload bytes.", filePathString.c_str());
    }

    // Write the payload bytes to the file.
    fout.write((const char *)this->payloadBytes.data(), this->payloadBytes.size());
}

void ROP::PayloadGenX86::writeScriptToFile(const std::string& filename) {
    const std::string& filePathString = GetPathToFileInSameParentDirectory(filename);

    // Open the file for writing.
    std::ofstream fout(filePathString);
    if (fout.fail()) {
        exitError("Can't open file (%s) for writing the script.", filePathString.c_str());
    }

    for (const std::string& line : this->pythonScript) {
        fout << line << '\n';
    }
}


