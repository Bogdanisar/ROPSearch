#include "PayloadGenX86.hpp"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <sstream>


void ROP::PayloadGenX86::preconfigureVMInstructionsObject() {
    VirtualMemoryInstructions::MaxInstructionsInInstructionSequence = 6;
    VirtualMemoryInstructions::SearchForSequencesWithDirectRelativeJumpsInTheMiddle = true;
    VirtualMemoryInstructions::IgnoreOutputSequencesThatStartWithDirectRelativeJumps = true;
    VirtualMemoryInstructions::innerAssemblySyntax = ROP::AssemblySyntax::Intel;
    VirtualMemoryInstructions::computeRegisterInfo = true;
}

void ROP::PayloadGenX86::preloadTheRegisterMaps() {
    BitSizeClass archSize = this->processArchSize;

    // Compute values for `this->regToMainReg` member.
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
            this->regToMainReg[currReg] = currReg;
        }
    }
    else {
        assert(archSize == BitSizeClass::BIT32);
        this->regToMainReg[X86_REG_RAX] = X86_REG_EAX;
        this->regToMainReg[X86_REG_RBX] = X86_REG_EBX;
        this->regToMainReg[X86_REG_RCX] = X86_REG_ECX;
        this->regToMainReg[X86_REG_RDX] = X86_REG_EDX;
        this->regToMainReg[X86_REG_RSI] = X86_REG_ESI;
        this->regToMainReg[X86_REG_RDI] = X86_REG_EDI;
        this->regToMainReg[X86_REG_RBP] = X86_REG_EBP;
        this->regToMainReg[X86_REG_RSP] = X86_REG_ESP;
        this->regToMainReg[X86_REG_RIP] = X86_REG_EIP;
    }

    // Compute values for `this->regToPartialRegs` member.
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
            this->regToPartialRegs[leader] = std::set<x86_reg>(regGroup.begin(), regGroup.end());
        }
        else {
            assert(archSize == BitSizeClass::BIT32);
            regGroup.erase(regGroup.begin());
            this->regToPartialRegs[leader] = std::set<x86_reg>(regGroup.begin(), regGroup.end());
        }
    }

    // Compute values for `this->regToEndingPartialRegs` member.
    for (const auto& it : this->regToPartialRegs) {
        x86_reg leader = it.first;
        std::set<x86_reg> regGroup = it.second;

        regGroup.erase(X86_REG_AH);
        regGroup.erase(X86_REG_BH);
        regGroup.erase(X86_REG_CH);
        regGroup.erase(X86_REG_DH);

        this->regToEndingPartialRegs[leader] = regGroup;
    }
}

void ROP::PayloadGenX86::computeRelevantSequenceIndexes() {
    assertMessage(this->instrSeqs.size() == this->regInfoSeqs.size(), "Inner logic error.");

    // Generate all indexes;
    for (unsigned idx = 0; idx < this->instrSeqs.size(); ++idx) {
        this->sequenceIndexList.push_back(idx);
    }

    // Sort the sequences by the length of the instruction sequence, increasingly.
    auto comparator = [&](unsigned idxA, unsigned idxB) {
        return (this->instrSeqs[idxA].second.size() < this->instrSeqs[idxB].second.size());
    };
    sort(this->sequenceIndexList.begin(), this->sequenceIndexList.end(), comparator);
}

ROP::PayloadGenX86::PayloadGenX86(int processPid) {
    this->preconfigureVMInstructionsObject();
    this->vmInstructionsObject = VirtualMemoryInstructions(processPid);
    this->instrSeqs = this->vmInstructionsObject.getInstructionSequences(&this->regInfoSeqs);
    this->computeRelevantSequenceIndexes();

    this->processArchSize = this->vmInstructionsObject.getVirtualMemoryBytes().getProcessArchSize();
    this->numBytesOfAddress = (this->processArchSize == BitSizeClass::BIT64) ? 8 : 4;

    this->preloadTheRegisterMaps();
}

ROP::PayloadGenX86::PayloadGenX86(const std::vector<std::string> execPaths,
                                  const std::vector<addressType> baseAddresses) {
    this->preconfigureVMInstructionsObject();
    this->vmInstructionsObject = VirtualMemoryInstructions(execPaths, baseAddresses);
    this->instrSeqs = this->vmInstructionsObject.getInstructionSequences(&this->regInfoSeqs);
    this->computeRelevantSequenceIndexes();

    this->processArchSize = this->vmInstructionsObject.getVirtualMemoryBytes().getProcessArchSize();
    this->numBytesOfAddress = (this->processArchSize == BitSizeClass::BIT64) ? 8 : 4;

    this->preloadTheRegisterMaps();
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

    this->payloadBytes.insert(this->payloadBytes.end(), addressBytes.begin(), addressBytes.end());

    std::ostringstream ss;

    ss << "# Instruction sequence: '" << sequenceString << "'";
    this->pythonScript.push_back(ss.str()); ss.str("");

    ss << "# Address: 0x";
    ss << std::hex << std::setfill('0');
    ss << std::setw(2 * this->numBytesOfAddress) << address;
    this->pythonScript.push_back(ss.str()); ss.str("");

    ss << "payload += b'";
    ss << std::hex << std::uppercase << std::setfill('0');
    for (ROP::byte currByte : addressBytes) {
        ss << "\\x" << std::setw(2) << (unsigned)currByte;
    }
    ss << "'";
    this->pythonScript.push_back(ss.str()); ss.str("");

    // New line;
    this->pythonScript.push_back("");
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

    this->payloadBytes.insert(this->payloadBytes.end(), bytes.begin(), bytes.end());

    std::ostringstream ss;
    ss << "# Value: 0x";
    ss << std::hex << std::setfill('0');
    ss << std::setw(2 * this->numBytesOfAddress) << cValue;
    this->pythonScript.push_back(ss.str()); ss.str("");

    ss << "payload += b'";
    ss << std::hex << std::uppercase << std::setfill('0');
    for (ROP::byte currByte : bytes) {
        ss << "\\x" << std::setw(2) << (unsigned)currByte;
    }
    ss << "'";
    this->pythonScript.push_back(ss.str()); ss.str("");
}

void ROP::PayloadGenX86::appendPaddingBytesToPayload(const unsigned numPaddingBytes) {
    if (numPaddingBytes == 0) {
        return;
    }

    this->payloadBytes.insert(this->payloadBytes.end(), numPaddingBytes, 0xFF);

    std::ostringstream ss;
    ss << "payload += b'0xFF' * " << numPaddingBytes;
    this->pythonScript.push_back(ss.str()); ss.str("");
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


unsigned ROP::PayloadGenX86::searchForSequenceStartingWithInstruction(const std::string& targetInstruction,
                                                                      const std::set<x86_reg>& forbiddenRegisters) {
    unsigned foundIndex = this->instrSeqs.size();
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

            bool instructionWritesToForbiddenRegisters = false;
            for (x86_reg forbiddenRegId : forbiddenRegisters) {
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

        if (sequenceIsGood) {
            foundIndex = sequenceIndex;
            break;
        }
    }

    return foundIndex;
}


bool ROP::PayloadGenX86::searchGadgetForAssignValueToRegister(x86_reg regKey,
                                                              const uint64_t cValue,
                                                              std::set<x86_reg> forbiddenRegisters,
                                                              bool shouldAppend) {
    std::string regString = InstructionConverter::convertCapstoneRegIdToShortStringLowercase(this->regToMainReg[regKey]);
    std::string targetInstruction = "pop " + regString;

    // Append the current target register (and the partial registers) to the list of forbidden registers;
    // Append the partial registers for RIP and RSP to the list of forbidden registers;
    const std::set<x86_reg>& localForbiddenRegs = this->regToPartialRegs[regKey];
    const std::set<x86_reg>& ripPartialRegs = this->regToPartialRegs[X86_REG_RIP];
    const std::set<x86_reg>& rspPartialRegs = this->regToPartialRegs[X86_REG_RSP];
    for (const auto& regSet : {localForbiddenRegs, ripPartialRegs, rspPartialRegs}) {
        forbiddenRegisters.insert(regSet.begin(), regSet.end());
    }

    unsigned sequenceIndex = this->searchForSequenceStartingWithInstruction(targetInstruction, forbiddenRegisters);
    if (sequenceIndex == this->instrSeqs.size()) {
        LogWarn("Can't find a useful instruction sequence containing \"%s\".", targetInstruction.c_str());
        return false;
    }

    if (shouldAppend) {
        this->appendInstructionSequenceToPayload(sequenceIndex);
        this->appendBytesOfRegisterSizedConstantToPayload(cValue);
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


