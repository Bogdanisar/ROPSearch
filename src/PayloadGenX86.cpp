#include "PayloadGenX86.hpp"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <sstream>


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


void ROP::PayloadGenX86::preloadTheRegisterMaps() {
    BitSizeClass archSize = this->processArchSize;

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
    };
    for (std::vector<x86_reg> regGroup : partialRegisterGroups) {
        x86_reg leader = regGroup[0];

        if (archSize == BitSizeClass::BIT64) {
            this->regKeyToPartialRegs[leader] = std::set<x86_reg>(regGroup.begin(), regGroup.end());
        }
        else {
            assert(archSize == BitSizeClass::BIT32);
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

void ROP::PayloadGenX86::preloadTheStackPointerInstructionToOffsetMap() {
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
    for (unsigned offset = 0; offset <= maxOffset; ++offset) {
        for (std::string regString : {"rsp", "esp", "sp", "spl"}) {
            char buff[10];
            memset(buff, 0, sizeof(buff));
            sprintf(buff, "%hhx", (unsigned char)offset);

            std::string instruction = "add " + regString + ", 0x" + buff;
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
            byteSequence addressBytes;
            if (this->processArchSize == BitSizeClass::BIT64) {
                addressBytes = BytesOfInteger((uint64_t)addr);
            }
            else {
                assert(this->processArchSize == BitSizeClass::BIT32);
                addressBytes = BytesOfInteger((uint32_t)addr);
            }

            bool addressHasNullBytes = false;
            for (const ROP::byte& currentAddressByte : addressBytes) {
                if (currentAddressByte == 0x00) {
                    addressHasNullBytes = true;
                    break;
                }
            }

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
}

void ROP::PayloadGenX86::configureGenerator() {
    if (this->numAcceptablePaddingBytesForOneInstruction > 400) {
        this->numAcceptablePaddingBytesForOneInstruction = 400;
    }

    this->processArchSize = this->vmInstructionsObject.getVirtualMemoryBytes().getProcessArchSize();
    this->numBytesOfAddress = (this->processArchSize == BitSizeClass::BIT64) ? 8 : 4;
    this->preloadTheRegisterMaps();
    this->preloadTheStackPointerInstructionToOffsetMap();

    this->instrSeqs = this->vmInstructionsObject.getInstructionSequences(&this->regInfoSeqs);
    this->computeRelevantSequenceIndexes();
}


void ROP::PayloadGenX86::addLineToPythonScript(const std::string& line, bool isComment) {
    std::string prefix = "";
    prefix.insert(0, this->currLineIndent * 4, ' ');
    if (isComment) {
        prefix.append("# ");
    }

    this->pythonScript.push_back(prefix + line);
}

void ROP::PayloadGenX86::appendInstructionSequenceToPayload(unsigned sequenceIndex,
                                                            bool isComment) {
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

    if (!isComment) {
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
    ss << "# 0x";
    ss << std::hex << std::nouppercase << std::setfill('0');
    ss << std::setw(2 * this->numBytesOfAddress) << address;
    ss << ": " << sequenceString;

    this->addLineToPythonScript(ss.str(), isComment);
}

void ROP::PayloadGenX86::appendBytesOfRegisterSizedConstantToPayload(const uint64_t cValue,
                                                                     bool isComment) {
    byteSequence bytes;
    if (this->processArchSize == BitSizeClass::BIT64) {
        bytes = BytesOfInteger((uint64_t)cValue);
    }
    else {
        assert(this->processArchSize == BitSizeClass::BIT32);
        bytes = BytesOfInteger((uint32_t)cValue);
    }

    if (!isComment) {
        this->payloadBytes.insert(this->payloadBytes.end(), bytes.begin(), bytes.end());
    }

    // Add "payload += b'...' # Value: 0x..." line.
    std::ostringstream ss;
    ss << "payload += b'";
    ss << std::hex << std::uppercase << std::setfill('0');
    for (ROP::byte currByte : bytes) {
        ss << "\\x" << std::setw(2) << (unsigned)currByte;
    }
    ss << "' # Value: 0x";
    ss << std::hex << std::setfill('0');
    ss << std::setw(2 * this->numBytesOfAddress) << cValue;
    this->addLineToPythonScript(ss.str(), isComment);
}

void ROP::PayloadGenX86::appendPaddingBytesToPayload(const unsigned numPaddingBytes,
                                                     bool isComment) {
    if (numPaddingBytes == 0) {
        return;
    }

    if (!isComment) {
        this->payloadBytes.insert(this->payloadBytes.end(), numPaddingBytes, 0xFF);
    }

    std::ostringstream ss;
    ss << "payload += b'0xFF' * " << numPaddingBytes;
    this->addLineToPythonScript(ss.str(), isComment);
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
    for (unsigned sequenceIndex : this->sequenceIndexList) {
        auto addressAndSequencePair = this->instrSeqs[sequenceIndex];
        addressType address = addressAndSequencePair.first;
        const std::vector<std::string>& currInstrSequence = addressAndSequencePair.second;
        const std::vector<RegisterInfo>& currRegInfoSequence = this->regInfoSeqs[sequenceIndex];
        UNUSED(address);

        // See if the first instruction in the sequence is the one that we want.
        assert(currInstrSequence.size() > 0);
        if (currInstrSequence[0] != targetInstruction) {
            continue;
        }

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


bool ROP::PayloadGenX86::appendGadgetForAssignValueToRegister(x86_reg regKey,
                                                              const uint64_t cValue,
                                                              std::set<x86_reg> forbiddenRegisterKeys,
                                                              bool shouldAppend) {
    std::string regString = InstructionConverter::convertCapstoneRegIdToShortStringLowercase(this->regKeyToMainReg[regKey]);
    std::string targetInstruction = "pop " + regString;
    forbiddenRegisterKeys.insert(regKey);

    std::vector<SequenceLookupResult> seqResults;
    seqResults = this->searchForSequenceStartingWithInstruction(targetInstruction,
                                                                forbiddenRegisterKeys);
    if (seqResults.size() == 0) {
        LogWarn("Can't find a useful instruction sequence containing \"%s\".", targetInstruction.c_str());
        return false;
    }

    if (shouldAppend) {
        std::string regStringUpper = InstructionConverter::convertCapstoneRegIdToShortString(this->regKeyToMainReg[regKey]);
        this->addLineToPythonScript("# " + regStringUpper + " = value;");
        this->addLineToPythonScript("if True:");

        this->currLineIndent++;
        unsigned numToOutput = this->getNumberOfVariantsToOutputForThisStep(seqResults.size());
        for (unsigned idx = 0; idx < numToOutput; ++idx) {
            bool isComment = (idx != 0);
            this->appendInstructionSequenceToPayload(seqResults[idx].index, isComment);
            this->appendBytesOfRegisterSizedConstantToPayload(cValue, isComment);
            this->appendPaddingBytesToPayload(seqResults[idx].numNeededPaddingBytes, isComment);
            this->addLineToPythonScript(""); // New line.
        }
        this->currLineIndent--;
    }

    return true;
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


