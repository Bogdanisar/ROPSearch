#include "InstructionConverter.hpp"

#include <capstone/capstone.h>
#include <keystone/keystone.h>



ROP::RegisterInfo ROP::RegisterInfo::reduceRegInfoListWithAndOperator(const std::vector<RegisterInfo> &infoList) {
	if (infoList.size() == 0) {
		return {};
	}

	RegisterInfo ret = infoList[0];
	for (unsigned idx = 1; idx < infoList.size(); ++idx) {
		ret.rRegs &= infoList[idx].rRegs;
		ret.wRegs &= infoList[idx].wRegs;
		ret.readsMemoryOperand = ret.readsMemoryOperand && infoList[idx].readsMemoryOperand;
		ret.writesMemoryOperand = ret.writesMemoryOperand && infoList[idx].writesMemoryOperand;
        ret.hasImmediateValue = ret.hasImmediateValue && infoList[idx].hasImmediateValue;
	}

	return ret;
}

ROP::RegisterInfo ROP::RegisterInfo::reduceRegInfoListWithOrOperator(const std::vector<RegisterInfo> &infoList) {
	if (infoList.size() == 0) {
		return {};
	}

	RegisterInfo ret = infoList[0];
	for (unsigned idx = 1; idx < infoList.size(); ++idx) {
		ret.rRegs |= infoList[idx].rRegs;
		ret.wRegs |= infoList[idx].wRegs;
		ret.readsMemoryOperand = ret.readsMemoryOperand || infoList[idx].readsMemoryOperand;
		ret.writesMemoryOperand = ret.writesMemoryOperand || infoList[idx].writesMemoryOperand;
        ret.hasImmediateValue = ret.hasImmediateValue || infoList[idx].hasImmediateValue;
	}

	return ret;
}


void ROP::InstructionConverter::initKeystone() {
    ks_err err;
    ks_mode mode;

    mode = (this->archBitSize == BitSizeClass::BIT32) ? KS_MODE_32 : KS_MODE_64;

    err = ks_open(KS_ARCH_X86, mode, &this->ksEngine);
    if (err != KS_ERR_OK) {
        exitError("Keystone: ks_open() failed with error %u!\n", (unsigned)err);
    }

    // Adjust the engine to use Intel syntax by default.
    err = ks_option(this->ksEngine, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
    if (err != KS_ERR_OK) {
        exitError("Keystone: ks_option() failed with error %u!\n", (unsigned)err);
    }

    this->ksEngineSyntax = AssemblySyntax::Intel;
}

void ROP::InstructionConverter::initCapstone() {
    cs_err err;
    cs_mode mode;

    mode = (this->archBitSize == BitSizeClass::BIT32) ? CS_MODE_32 : CS_MODE_64;

	err = cs_open(CS_ARCH_X86, mode, &this->capstoneHandle);
    if (err != CS_ERR_OK) {
        exitError("Capstone: cs_open() failed with error %u!\n", (unsigned)err);
    }

    // Adjust the engine to use Intel syntax by default.
    err = cs_option(this->capstoneHandle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
    if (err != CS_ERR_OK) {
        exitError("Capstone: cs_option() failed with error %u!\n", (unsigned)err);
    }

    err = cs_option(this->capstoneHandle, CS_OPT_DETAIL, CS_OPT_OFF);
    if (err != CS_ERR_OK) {
        exitError("Capstone: cs_option() failed with error %u!", (unsigned)err);
    }

    this->csHandleSyntax = AssemblySyntax::Intel;
    this->csHandleDetailModeEnabled = false;
}

ROP::InstructionConverter::InstructionConverter(BitSizeClass archBitSize) {
    this->archBitSize = archBitSize;
    this->initKeystone();
    this->initCapstone();
}


inline bool ROP::InstructionConverter::updateKeystoneAssemblySetting(AssemblySyntax newAsmSyntax) {
    if (this->ksEngineSyntax == newAsmSyntax) {
        return true;
    }

    ks_opt_value newSettingValue;
    newSettingValue = (newAsmSyntax == AssemblySyntax::Intel) ? KS_OPT_SYNTAX_INTEL : KS_OPT_SYNTAX_ATT;

    ks_err err = ks_option(this->ksEngine, KS_OPT_SYNTAX, newSettingValue);
    if (err != KS_ERR_OK) {
        LogError("Keystone: ks_option(KS_OPT_SYNTAX, %u) failed with error %u!",
                 (unsigned)newSettingValue, (unsigned)err);
        return false;
    }

    this->ksEngineSyntax = newAsmSyntax;
    return true;
}

inline bool ROP::InstructionConverter::updateCapstoneAssemblySetting(AssemblySyntax newAsmSyntax) {
    if (this->csHandleSyntax == newAsmSyntax) {
        return true;
    }

    cs_opt_value newSettingValue;
    newSettingValue = (newAsmSyntax == AssemblySyntax::Intel) ? CS_OPT_SYNTAX_INTEL : CS_OPT_SYNTAX_ATT;

    cs_err err = cs_option(this->capstoneHandle, CS_OPT_SYNTAX, newSettingValue);
    if (err != CS_ERR_OK) {
        LogError("Capstone: cs_option(CS_OPT_SYNTAX, %u) failed with error %u!",
                 (unsigned)newSettingValue, (unsigned)err);
        return false;
    }

    this->csHandleSyntax = newAsmSyntax;
    return true;
}

inline bool ROP::InstructionConverter::updateCapstoneDetailSetting(bool detailsEnabled) {
    if (this->csHandleDetailModeEnabled == detailsEnabled) {
        return true;
    }

    cs_opt_value newSettingValue;
    newSettingValue = detailsEnabled ? CS_OPT_ON : CS_OPT_OFF;

    cs_err err = cs_option(this->capstoneHandle, CS_OPT_DETAIL, newSettingValue);
    if (err != CS_ERR_OK) {
        LogError("Capstone: cs_option(CS_OPT_DETAIL, %u) failed with error %u!",
                 (unsigned)newSettingValue, (unsigned)err);
        return false;
    }

    this->csHandleDetailModeEnabled = detailsEnabled;
    return true;
}


std::pair<ROP::byteSequence, unsigned>
ROP::InstructionConverter::convertInstructionSequenceToBytes(
    std::string instructionSequenceAsm,
    AssemblySyntax asmSyntax,
    addressType addr
) {
    byteSequence instructionSequence;

    const char * const insSeqCString = instructionSequenceAsm.c_str();
    unsigned char *insSeqEncoding = NULL;
    size_t insSeqEncodingSize;
    size_t numDecodedInstructions;

    if (!this->updateKeystoneAssemblySetting(asmSyntax)) {
        goto cleanup;
    }

    if (ks_asm(this->ksEngine, insSeqCString, addr, &insSeqEncoding, &insSeqEncodingSize, &numDecodedInstructions) != 0) {
        LogError("Keystone: ks_asm() failed with error %u; Number of decoded instructions = %u;",
                 (unsigned)ks_errno(this->ksEngine), (unsigned)numDecodedInstructions);
        goto cleanup;
    }

    for (size_t i = 0; i < insSeqEncodingSize; ++i) {
        instructionSequence.push_back((byte)insSeqEncoding[i]);
    }

cleanup:
    // Free the bytes generated by Keystone.
    if (insSeqEncoding != NULL) {
        ks_free(insSeqEncoding);
    }

// Final
    if (instructionSequence.size() == 0) {
        pv(instructionSequenceAsm); pn;
        pv(numDecodedInstructions); pn;
        exitError("Keystone conversion from instruction sequence string to instruction sequence bytes failed");
    }

    return {instructionSequence, numDecodedInstructions};
}

unsigned
ROP::InstructionConverter::convertInstructionSequenceToString(
    const byte * const instrSeqBytes,
    const size_t instrSeqBytesCount,
    AssemblySyntax asmSyntax,
    addressType addr,
    const size_t parseCount,
    std::vector<std::string> *outInstructionAsm,
    std::vector<RegisterInfo> *outRegInfo
) {
    cs_err err;
	cs_insn *decodedInstructions = NULL;
	size_t decodedInstructionsCount;
    size_t idx;
    unsigned totalDecodedBytes = 0;

    (*outInstructionAsm).clear();

	// Update the settings of the Capstone handle.
	if (!this->updateCapstoneAssemblySetting(asmSyntax)) {
		goto cleanup;
	}
	if (!this->updateCapstoneDetailSetting(outRegInfo != NULL)) {
		goto cleanup;
	}

	decodedInstructionsCount = cs_disasm(this->capstoneHandle,
                                         (const uint8_t *)instrSeqBytes,
                                         instrSeqBytesCount,
                                         addr, // Address of first instruction
                                         parseCount,
                                         &decodedInstructions);
    err = cs_errno(this->capstoneHandle);
    if (decodedInstructionsCount == 0 && err != CS_ERR_OK) {
        LogError("Capstone: cs_disasm() failed with error %u", (unsigned)err);
        goto cleanup;
    }

    for (idx = 0; idx < decodedInstructionsCount; ++idx) {
        std::string mnemonic = std::string(decodedInstructions[idx].mnemonic);
        std::string operands = std::string(decodedInstructions[idx].op_str);

        std::string instructionAsm = mnemonic;
        if (operands.size() != 0) {
            instructionAsm += " " + operands;
        }

        totalDecodedBytes += decodedInstructions[idx].size;
        (*outInstructionAsm).push_back(instructionAsm);

        if (outRegInfo != NULL) {
            RegisterInfo ri;


			// Determine which registers are read or written.
            cs_regs regsRead, regsWritten;
            uint8_t readCount = 0, writeCount = 0;
            cs_err regsRet = cs_regs_access(this->capstoneHandle, &decodedInstructions[idx],
                                            regsRead, &readCount, regsWritten, &writeCount);
            if (regsRet != CS_ERR_OK) {
                LogError("Capstone: cs_regs_access() failed with error %u", (unsigned)regsRet);
                goto cleanup;
            }

            for (uint8_t i = 0; i < readCount; ++i) {
                size_t registerIndex = regsRead[i];
                ri.rRegs.set(registerIndex, true);
            }
            for (uint8_t i = 0; i < writeCount; ++i) {
                size_t registerIndex = regsWritten[i];
                ri.wRegs.set(registerIndex, true);
            }


			// Determine if memory operands are read or written.
			ri.readsMemoryOperand = ri.writesMemoryOperand = false;
			uint8_t op_count = decodedInstructions[idx].detail->x86.op_count;

			for (uint8_t i = 0; i < op_count; ++i) {
				const cs_x86_op& operand = decodedInstructions[idx].detail->x86.operands[i];
				if (operand.type != X86_OP_MEM) {
					continue;
				}

				if (operand.access & CS_AC_READ) {
					ri.readsMemoryOperand = true;
				}
				if (operand.access & CS_AC_WRITE) {
					ri.writesMemoryOperand = true;
				}
			}


			// Determine if the instruction has an immediate value;
            ri.hasImmediateValue = (decodedInstructions[idx].detail->x86.encoding.imm_offset != 0);


            (*outRegInfo).push_back(ri);
        }
    }

cleanup:
    if (decodedInstructions != NULL) {
        cs_free(decodedInstructions, decodedInstructionsCount);
    }

// Final
    return totalDecodedBytes;
}

unsigned
ROP::InstructionConverter::convertInstructionSequenceToString(
    const byteSequence& instructionSequence,
    AssemblySyntax asmSyntax,
    addressType addr,
    const size_t parseCount,
    std::vector<std::string> *outInstructionAsm,
    std::vector<RegisterInfo> *outRegInfo
) {
    const byte *instrSeqBytes = (const byte *)instructionSequence.data();
    const size_t instrSeqBytesCount = instructionSequence.size();
    return this->convertInstructionSequenceToString(instrSeqBytes,
                                                    instrSeqBytesCount,
                                                    asmSyntax,
                                                    addr,
                                                    parseCount,
                                                    outInstructionAsm,
                                                    outRegInfo);
}

std::vector<std::string>
ROP::InstructionConverter::normalizeInstructionAsm(std::string origInsSequenceAsm,
                                                   ROP::AssemblySyntax inputAsmSyntax,
                                                   ROP::AssemblySyntax outputAsmSyntax) {
    const byteSequence& insSeqBytes = this->convertInstructionSequenceToBytes(origInsSequenceAsm, inputAsmSyntax).first;

    std::vector<std::string> instructions;
    auto convertedBytes = this->convertInstructionSequenceToString(insSeqBytes, outputAsmSyntax, 0, 0, &instructions);
    assert(convertedBytes == insSeqBytes.size());

    return instructions;
}

std::string
ROP::InstructionConverter::concatenateInstructionsAsm(std::vector<std::string> instructionsAsm) {
    std::string ret = "";

    for (size_t i = 0; i < instructionsAsm.size(); ++i) {
        ret = (ret + instructionsAsm[i]);
        if (i != instructionsAsm.size() - 1) {
            ret += "; ";
        }
    }

    return ret;
}


static std::string ConcatenateRegisterIDListIntoString(std::vector<x86_reg> regList) {
    std::stringstream regStringStream;

    unsigned count = regList.size();
    for (unsigned i = 0; i < count; ++i) {
        x86_reg regID = regList[i];
        const char * regName = ROP::InstructionConverter::convertCapstoneRegIdToShortString(regID);
        regStringStream << regName;
        if (i != count - 1) {
            regStringStream << ", ";
        }
    }

    return regStringStream.str();
}

void
ROP::InstructionConverter::printCapstoneInformationForInstructions(std::string instructionSequenceAsm,
                                                                   AssemblySyntax inputAsmSyntax,
                                                                   addressType addr) {
    // Trim a trailing ';' character if it exists, for convenience.
    // The ';' character is supposed to be placed only between instructions.
    RightTrimString(instructionSequenceAsm, "; \t\n\r\f\v");

    // Convert the input ASM string to bytes.
	auto convertedInputPair = this->convertInstructionSequenceToBytes(instructionSequenceAsm, inputAsmSyntax, addr);
	byteSequence bytesVector = convertedInputPair.first;

    const byte *instrSeqBytes = (const byte *)bytesVector.data();
    const size_t instrSeqBytesCount = bytesVector.size();


	// Pass the bytes to Capstone to get detailed information about the instructions.
	cs_err err;
	cs_insn *decodedInstructions = NULL;
	size_t decodedInstructionsCount;
    size_t idx;
    unsigned totalDecodedBytes = 0;

	// Update the settings of the Capstone handle.
	if (!this->updateCapstoneAssemblySetting(inputAsmSyntax)) {
		goto cleanup;
	}
	if (!this->updateCapstoneDetailSetting(true)) {
		goto cleanup;
	}

	decodedInstructionsCount = cs_disasm(this->capstoneHandle,
                                         (const uint8_t *)instrSeqBytes,
                                         instrSeqBytesCount,
                                         addr, // Address of first instruction
                                         0,
                                         &decodedInstructions);

    err = cs_errno(this->capstoneHandle);
    if (decodedInstructionsCount == 0 && err != CS_ERR_OK) {
        LogError("Capstone: cs_disasm() failed with error %u", (unsigned)err);
        goto cleanup;
    }

    LogInfo(""); // New line.

    for (idx = 0; idx < decodedInstructionsCount; ++idx) {
        if (decodedInstructionsCount > 1) {
            LogInfo("########### Instruction %u ###########", (unsigned)idx);
        }

        const cs_insn& instr = decodedInstructions[idx];

        // Print the assembly representation.
        std::string mnemonic = std::string(decodedInstructions[idx].mnemonic);
        std::string operands = std::string(decodedInstructions[idx].op_str);
        std::string instructionAsm = mnemonic;
        if (operands.size() != 0) {
            instructionAsm += " " + operands;
        }
        LogInfo("Assembly string: \"%s\"", instructionAsm.c_str());
        LogVerbose("Mnemonic string: \"%s\"", instr.mnemonic);
        LogVerbose("Operands string: \"%s\"", instr.op_str);

        // Print id and virtual address. The address is derived from the `addr` function parameter.
        LogInfo("Capstone id: %u", (unsigned)instr.id);
        LogInfo("Virtual address: 0x%llX", (unsigned long long)instr.address);


        // Print all registers that are *implicitly* read or written by the instruction.
        {
            std::vector<x86_reg> readRegList;
            for (uint8_t i = 0; i < instr.detail->regs_read_count; ++i) {
                x86_reg regID = (x86_reg)instr.detail->regs_read[i];
                readRegList.push_back(regID);
            }
            std::string readRegString = ConcatenateRegisterIDListIntoString(readRegList);
            if (readRegString == "") {
                readRegString = "N/A";
            }
            LogInfo("[Implicitly]    Read registers: %s", readRegString.c_str());

            std::vector<x86_reg> writtenRegList;
            for (uint8_t i = 0; i < instr.detail->regs_write_count; ++i) {
                x86_reg regID = (x86_reg)instr.detail->regs_write[i];
                writtenRegList.push_back(regID);
            }
            std::string writtenRegString = ConcatenateRegisterIDListIntoString(writtenRegList);
            if (writtenRegString == "") {
                writtenRegString = "N/A";
            }
            LogInfo("[Implicitly] Written registers: %s", writtenRegString.c_str());
        }

        // Print all registers that are read or written by the instruction
        // (whether implicitly or explicitly).
        {
            cs_regs regsRead, regsWritten;
            uint8_t readCount = 0, writeCount = 0;
            cs_err allRegsRet = cs_regs_access(this->capstoneHandle, &instr,
                                               regsRead, &readCount, regsWritten, &writeCount);
            if (allRegsRet != CS_ERR_OK) {
                LogError("Capstone: cs_regs_access() failed with error %u", (unsigned)allRegsRet);
                goto cleanup;
            }

            std::vector<x86_reg> readRegList;
            for (uint8_t i = 0; i < readCount; ++i) {
                x86_reg regID = (x86_reg)regsRead[i];
                readRegList.push_back(regID);
            }
            std::string readRegString = ConcatenateRegisterIDListIntoString(readRegList);
            if (readRegString == "") {
                readRegString = "N/A";
            }
            LogInfo("[Implicitly or Explicitly]    Read registers: %s", readRegString.c_str());

            std::vector<x86_reg> writtenRegList;
            for (uint8_t i = 0; i < writeCount; ++i) {
                x86_reg regID = (x86_reg)regsWritten[i];
                writtenRegList.push_back(regID);
            }
            std::string writtenRegString = ConcatenateRegisterIDListIntoString(writtenRegList);
            if (writtenRegString == "") {
                writtenRegString = "N/A";
            }
            LogInfo("[Implicitly or Explicitly] Written registers: %s", writtenRegString.c_str());
        }

        if (instr.detail->x86.op_count != 0) {
            LogInfo("Instruction has %u operand(s):", (unsigned)instr.detail->x86.op_count);
            for (unsigned k = 0; k < instr.detail->x86.op_count; ++k) {
                cs_x86_op& operand = instr.detail->x86.operands[k];

                std::string operandTypeString = "Invalid";
                if (operand.type == X86_OP_REG) {
                    const char * const regName = InstructionConverter::convertCapstoneRegIdToShortString(operand.reg);
                    std::string regNameString = regName;
                    RightPadString(regNameString, 9, ' ');

                    operandTypeString = std::string("Register ") + regNameString;
                }
                else if (operand.type == X86_OP_IMM) {
                    operandTypeString = "Immediate value   ";
                }
                else if (operand.type == X86_OP_MEM) {
                    operandTypeString = "Memory dereference";
                }

                std::string accessString = "none";
                if (operand.access == CS_AC_READ_WRITE) {
                    accessString = "read & write";
                }
                else if (operand.access == CS_AC_READ) {
                    accessString = "read";
                }
                else if (operand.access == CS_AC_WRITE) {
                    accessString = "write";
                }

                LogInfo("    Operand #%u: %s (Size: %u; Access: %s)",
                        k, operandTypeString.c_str(), (unsigned)operand.size, accessString.c_str());
            }
        }
        else {
            LogVerbose("Instruction has no operands");
        }

        LogInfo(""); // New line.


        // Print bytes
        LogInfo("Byte count: %u", (unsigned)instr.size);
        totalDecodedBytes += (unsigned)instr.size;

        {
            std::stringstream bytesStringStream;
            bytesStringStream << '[' << std::setfill(' ');
            for (unsigned byteIdx = 0; byteIdx < instr.size; ++byteIdx) {
                bytesStringStream << std::setw(3) << (unsigned)instr.bytes[byteIdx];

                if (byteIdx != (unsigned)(instr.size - 1)) {
                    bytesStringStream << ", ";
                }
            }
            bytesStringStream << ']';
            LogInfo("Bytes dec: %s", bytesStringStream.str().c_str());
        }
        {
            std::stringstream bytesStringStream;
            bytesStringStream << "[ " << std::hex << std::uppercase << std::setfill('0');
            for (unsigned byteIdx = 0; byteIdx < instr.size; ++byteIdx) {
                bytesStringStream << std::setw(2) << (unsigned)instr.bytes[byteIdx];

                if (byteIdx != (unsigned)(instr.size - 1)) {
                    bytesStringStream << ",  ";
                }
            }
            bytesStringStream << ']';
            LogInfo("Bytes hex: %s", bytesStringStream.str().c_str());
        }


        // Print prefix bytes.
        unsigned prefixByteCount = 0;
        for (unsigned prefixIdx = 0; prefixIdx < 4; ++prefixIdx) {
            if (instr.detail->x86.prefix[prefixIdx] != 0) {
                prefixByteCount += 1;
            }
        }

        if (prefixByteCount != 0) {
            LogInfo("Prefix bytes count: %u", prefixByteCount);

            std::vector<const char *> prefixLogStrings = {
                "REP/REPNE/LOCK",
                "segment override",
                "operand-size override",
                "address-size override",
            };
            for (unsigned prefixIdx = 0; prefixIdx < 4; ++prefixIdx) {
                unsigned char byte = instr.detail->x86.prefix[prefixIdx];
                if (byte != 0) {
                    LogInfo("    \"%s\" prefix byte: 0x%hhX",
                            prefixLogStrings[prefixIdx], byte);
                }
            }
        }
        else {
            LogVerbose("No prefix bytes.");
        }


        // Print REX byte.
        if (instr.detail->x86.rex != 0) {
            LogInfo("REX byte: 0x%02hhX", (unsigned char)instr.detail->x86.rex);
        }
        else {
            LogVerbose("REX byte: N/A");
        }

        // Print opcode bytes.
        {
            std::stringstream bytesStringStream;
            bytesStringStream << '[' << std::hex << std::uppercase << std::setfill('0');
            unsigned byteIdx = 0;
            while (instr.detail->x86.opcode[byteIdx] != 0) {
                if (byteIdx != 0) {
                    bytesStringStream << ", ";
                }
                bytesStringStream << "0x" << std::setw(2) << (unsigned)instr.detail->x86.opcode[byteIdx];

                ++byteIdx;
            }
            bytesStringStream << ']';
            LogInfo("Opcode bytes: %s", bytesStringStream.str().c_str());
        }

        // Print ModR/M byte.
        if (instr.detail->x86.encoding.modrm_offset != 0) {
            std::string binaryRepr = GetBinaryReprOfInteger((unsigned char)instr.detail->x86.modrm);
            LogInfo("ModR/M byte: 0x%02hhX (binary: %s %s %s)",
                    (unsigned char)instr.detail->x86.modrm,
                    binaryRepr.substr(0, 2).c_str(),
                    binaryRepr.substr(2, 3).c_str(),
                    binaryRepr.substr(5, 3).c_str());
        }
        else {
            LogVerbose("ModR/M byte: N/A");
        }

        // Print SIB byte.
        if (instr.detail->x86.sib != 0) {
            LogInfo("SIB byte: 0x%02hhX (base: %s; index: %s; scale: %hhu)",
                    (unsigned char)instr.detail->x86.sib,
                    InstructionConverter::convertCapstoneRegIdToShortString(instr.detail->x86.sib_base),
                    InstructionConverter::convertCapstoneRegIdToShortString(instr.detail->x86.sib_index),
                    instr.detail->x86.sib_scale);

            std::string binaryRepr = GetBinaryReprOfInteger((unsigned char)instr.detail->x86.sib);
            LogInfo("SIB byte:  0b%s  (value: 0x%02hhX)",
                    binaryRepr.c_str(),
                    (unsigned char)instr.detail->x86.sib);
            LogInfo("SIB scale:   %s        (value: %hhu)",
                    binaryRepr.substr(0, 2).c_str(), (unsigned char)instr.detail->x86.sib_scale);
            LogInfo("SIB index:     %s     (meaning: %s)",
                    binaryRepr.substr(2, 3).c_str(),
                    InstructionConverter::convertCapstoneRegIdToShortString(instr.detail->x86.sib_index));
            LogInfo("SIB base:         %s  (meaning: %s)",
                    binaryRepr.substr(5, 3).c_str(),
                    InstructionConverter::convertCapstoneRegIdToShortString(instr.detail->x86.sib_base));
        }
        else {
            LogVerbose("SIB byte: N/A");
        }

        // Print displacement.
        if (instr.detail->x86.encoding.disp_offset != 0) {
            unsigned printWidth = 2 * instr.detail->x86.encoding.disp_size;
            uint64_t displacement;

            // The following truncations are done since it seems that the .disp value
            // has some non-zero bytes added in the more-significant positions.
            if (instr.detail->x86.encoding.disp_size == 1) {
                displacement = (uint64_t)(uint8_t)instr.detail->x86.disp;
            }
            else if (instr.detail->x86.encoding.disp_size == 2) {
                displacement = (uint64_t)(uint16_t)instr.detail->x86.disp;
            }
            else if (instr.detail->x86.encoding.disp_size == 4) {
                displacement = (uint64_t)(uint32_t)instr.detail->x86.disp;
            }
            else if (instr.detail->x86.encoding.disp_size == 8) {
                displacement = (uint64_t)instr.detail->x86.disp;
            }

            LogInfo("Displacement: 0x%0*llX (Byte size: %u; Instruction byte offset: %u)",
                    printWidth, (unsigned long long)displacement,
                    (unsigned)instr.detail->x86.encoding.disp_size,
                    (unsigned)instr.detail->x86.encoding.disp_offset);
        }
        else {
            LogVerbose("Displacement: N/A");
        }

        // Print immediate value.
        if (instr.detail->x86.encoding.imm_offset != 0) {
            unsigned printWidth = 2 * instr.detail->x86.encoding.imm_size;
            unsigned offset = instr.detail->x86.encoding.imm_offset;

            uint64_t immediate = 0;
            for (unsigned k = 0; k < instr.detail->x86.encoding.imm_size; ++k) {
                unsigned char byte = instr.bytes[offset + k];

                // Adding at this position makes sense because x86 is always encoded as little-endian.
                immediate = immediate | (byte << (k * 8));
            }

            LogInfo("Immediate value: 0x%0*llX (Byte count: %u; Instruction byte offset: %u)",
                    printWidth, (unsigned long long)immediate,
                    (unsigned)instr.detail->x86.encoding.imm_size,
                    (unsigned)instr.detail->x86.encoding.imm_offset);
        }
        else {
            LogVerbose("Immediate value: N/A");
        }

        LogVerbose(""); // New line.


        // Print the groups to which this instruction belongs.
        std::string groupsString("");
        for (uint8_t i = 0; i < instr.detail->groups_count; ++i) {
            cs_group_type groupID = (cs_group_type)instr.detail->groups[i];
            const char * groupName = cs_group_name(this->capstoneHandle, (unsigned int)groupID);

            groupsString += groupName;
            if (i != (instr.detail->groups_count - 1)) {
                groupsString += ", ";
            }
        }
        LogVerbose("Semantic instruction-group count: %u", (unsigned)instr.detail->groups_count);
        if (instr.detail->groups_count != 0) {
            LogVerbose("Semantic instruction-group names: %s", groupsString.c_str());
        }

        // Print the "writeback" member.
        LogVerbose("Has \"writeback\" operands: %i", (int)instr.detail->writeback);

        // Print address-size member (not sure what this is).
        LogVerbose("Address size: %hhu", (unsigned char)instr.detail->x86.addr_size);


        // TODO: Print instr.detail->x86.eflags and instr.detail->x86.fpu_flags members as well?
        // X86_EFLAGS_SET_AF;
        // X86_FPU_FLAGS_SET_C0;


        if (decodedInstructionsCount > 1) {
            LogInfo("########### Instruction %u ###########", (unsigned)idx);
        }
        LogInfo(""); // New line.
    }

    assertMessage(instrSeqBytesCount == totalDecodedBytes,
                  "The number of bytes decoded by Keystone from the initial string is not the same as "
                  "the number of bytes successfully parsed back by Capstone (%u != %u).",
                  (unsigned)instrSeqBytesCount, (unsigned)totalDecodedBytes);

cleanup:
    if (decodedInstructions != NULL) {
        cs_free(decodedInstructions, decodedInstructionsCount);
    }
}


ROP::InstructionConverter::~InstructionConverter() {
    // Close the Keystone instance.
    ks_close(this->ksEngine);

    // Close the Capstone instance.
    cs_close(&this->capstoneHandle);
}



#pragma region Static methods
#if false
int ________Static_methods________;
#endif

#define X86_REG_LIST \
    X86_REG_USE(X86_REG_AH) \
	X86_REG_USE(X86_REG_AL) \
	X86_REG_USE(X86_REG_AX) \
	X86_REG_USE(X86_REG_BH) \
	X86_REG_USE(X86_REG_BL) \
	X86_REG_USE(X86_REG_BP) \
	X86_REG_USE(X86_REG_BPL) \
	X86_REG_USE(X86_REG_BX) \
	X86_REG_USE(X86_REG_CH) \
	X86_REG_USE(X86_REG_CL) \
	X86_REG_USE(X86_REG_CS) \
	X86_REG_USE(X86_REG_CX) \
	X86_REG_USE(X86_REG_DH) \
	X86_REG_USE(X86_REG_DI) \
	X86_REG_USE(X86_REG_DIL) \
	X86_REG_USE(X86_REG_DL) \
	X86_REG_USE(X86_REG_DS) \
	X86_REG_USE(X86_REG_DX) \
	X86_REG_USE(X86_REG_EAX) \
	X86_REG_USE(X86_REG_EBP) \
	X86_REG_USE(X86_REG_EBX) \
	X86_REG_USE(X86_REG_ECX) \
	X86_REG_USE(X86_REG_EDI) \
	X86_REG_USE(X86_REG_EDX) \
	X86_REG_USE(X86_REG_EFLAGS) \
	X86_REG_USE(X86_REG_EIP) \
	X86_REG_USE(X86_REG_EIZ) \
	X86_REG_USE(X86_REG_ES) \
	X86_REG_USE(X86_REG_ESI) \
	X86_REG_USE(X86_REG_ESP) \
	X86_REG_USE(X86_REG_FPSW) \
	X86_REG_USE(X86_REG_FS) \
	X86_REG_USE(X86_REG_GS) \
	X86_REG_USE(X86_REG_IP) \
	X86_REG_USE(X86_REG_RAX) \
	X86_REG_USE(X86_REG_RBP) \
	X86_REG_USE(X86_REG_RBX) \
	X86_REG_USE(X86_REG_RCX) \
	X86_REG_USE(X86_REG_RDI) \
	X86_REG_USE(X86_REG_RDX) \
	X86_REG_USE(X86_REG_RIP) \
	X86_REG_USE(X86_REG_RIZ) \
	X86_REG_USE(X86_REG_RSI) \
	X86_REG_USE(X86_REG_RSP) \
	X86_REG_USE(X86_REG_SI) \
	X86_REG_USE(X86_REG_SIL) \
	X86_REG_USE(X86_REG_SP) \
	X86_REG_USE(X86_REG_SPL) \
	X86_REG_USE(X86_REG_SS) \
	X86_REG_USE(X86_REG_CR0) \
	X86_REG_USE(X86_REG_CR1) \
	X86_REG_USE(X86_REG_CR2) \
	X86_REG_USE(X86_REG_CR3) \
	X86_REG_USE(X86_REG_CR4) \
	X86_REG_USE(X86_REG_CR5) \
	X86_REG_USE(X86_REG_CR6) \
	X86_REG_USE(X86_REG_CR7) \
	X86_REG_USE(X86_REG_CR8) \
	X86_REG_USE(X86_REG_CR9) \
	X86_REG_USE(X86_REG_CR10) \
	X86_REG_USE(X86_REG_CR11) \
	X86_REG_USE(X86_REG_CR12) \
	X86_REG_USE(X86_REG_CR13) \
	X86_REG_USE(X86_REG_CR14) \
	X86_REG_USE(X86_REG_CR15) \
	X86_REG_USE(X86_REG_DR0) \
	X86_REG_USE(X86_REG_DR1) \
	X86_REG_USE(X86_REG_DR2) \
	X86_REG_USE(X86_REG_DR3) \
	X86_REG_USE(X86_REG_DR4) \
	X86_REG_USE(X86_REG_DR5) \
	X86_REG_USE(X86_REG_DR6) \
	X86_REG_USE(X86_REG_DR7) \
	X86_REG_USE(X86_REG_DR8) \
	X86_REG_USE(X86_REG_DR9) \
	X86_REG_USE(X86_REG_DR10) \
	X86_REG_USE(X86_REG_DR11) \
	X86_REG_USE(X86_REG_DR12) \
	X86_REG_USE(X86_REG_DR13) \
	X86_REG_USE(X86_REG_DR14) \
	X86_REG_USE(X86_REG_DR15) \
	X86_REG_USE(X86_REG_FP0) \
	X86_REG_USE(X86_REG_FP1) \
	X86_REG_USE(X86_REG_FP2) \
	X86_REG_USE(X86_REG_FP3) \
	X86_REG_USE(X86_REG_FP4) \
	X86_REG_USE(X86_REG_FP5) \
	X86_REG_USE(X86_REG_FP6) \
	X86_REG_USE(X86_REG_FP7) \
	X86_REG_USE(X86_REG_K0) \
	X86_REG_USE(X86_REG_K1) \
	X86_REG_USE(X86_REG_K2) \
	X86_REG_USE(X86_REG_K3) \
	X86_REG_USE(X86_REG_K4) \
	X86_REG_USE(X86_REG_K5) \
	X86_REG_USE(X86_REG_K6) \
	X86_REG_USE(X86_REG_K7) \
	X86_REG_USE(X86_REG_MM0) \
	X86_REG_USE(X86_REG_MM1) \
	X86_REG_USE(X86_REG_MM2) \
	X86_REG_USE(X86_REG_MM3) \
	X86_REG_USE(X86_REG_MM4) \
	X86_REG_USE(X86_REG_MM5) \
	X86_REG_USE(X86_REG_MM6) \
	X86_REG_USE(X86_REG_MM7) \
	X86_REG_USE(X86_REG_R8) \
	X86_REG_USE(X86_REG_R9) \
	X86_REG_USE(X86_REG_R10) \
	X86_REG_USE(X86_REG_R11) \
	X86_REG_USE(X86_REG_R12) \
	X86_REG_USE(X86_REG_R13) \
	X86_REG_USE(X86_REG_R14) \
	X86_REG_USE(X86_REG_R15) \
	X86_REG_USE(X86_REG_ST0) \
	X86_REG_USE(X86_REG_ST1) \
	X86_REG_USE(X86_REG_ST2) \
	X86_REG_USE(X86_REG_ST3) \
	X86_REG_USE(X86_REG_ST4) \
	X86_REG_USE(X86_REG_ST5) \
	X86_REG_USE(X86_REG_ST6) \
	X86_REG_USE(X86_REG_ST7) \
	X86_REG_USE(X86_REG_XMM0) \
	X86_REG_USE(X86_REG_XMM1) \
	X86_REG_USE(X86_REG_XMM2) \
	X86_REG_USE(X86_REG_XMM3) \
	X86_REG_USE(X86_REG_XMM4) \
	X86_REG_USE(X86_REG_XMM5) \
	X86_REG_USE(X86_REG_XMM6) \
	X86_REG_USE(X86_REG_XMM7) \
	X86_REG_USE(X86_REG_XMM8) \
	X86_REG_USE(X86_REG_XMM9) \
	X86_REG_USE(X86_REG_XMM10) \
	X86_REG_USE(X86_REG_XMM11) \
	X86_REG_USE(X86_REG_XMM12) \
	X86_REG_USE(X86_REG_XMM13) \
	X86_REG_USE(X86_REG_XMM14) \
	X86_REG_USE(X86_REG_XMM15) \
	X86_REG_USE(X86_REG_XMM16) \
	X86_REG_USE(X86_REG_XMM17) \
	X86_REG_USE(X86_REG_XMM18) \
	X86_REG_USE(X86_REG_XMM19) \
	X86_REG_USE(X86_REG_XMM20) \
	X86_REG_USE(X86_REG_XMM21) \
	X86_REG_USE(X86_REG_XMM22) \
	X86_REG_USE(X86_REG_XMM23) \
	X86_REG_USE(X86_REG_XMM24) \
	X86_REG_USE(X86_REG_XMM25) \
	X86_REG_USE(X86_REG_XMM26) \
	X86_REG_USE(X86_REG_XMM27) \
	X86_REG_USE(X86_REG_XMM28) \
	X86_REG_USE(X86_REG_XMM29) \
	X86_REG_USE(X86_REG_XMM30) \
	X86_REG_USE(X86_REG_XMM31) \
	X86_REG_USE(X86_REG_YMM0) \
	X86_REG_USE(X86_REG_YMM1) \
	X86_REG_USE(X86_REG_YMM2) \
	X86_REG_USE(X86_REG_YMM3) \
	X86_REG_USE(X86_REG_YMM4) \
	X86_REG_USE(X86_REG_YMM5) \
	X86_REG_USE(X86_REG_YMM6) \
	X86_REG_USE(X86_REG_YMM7) \
	X86_REG_USE(X86_REG_YMM8) \
	X86_REG_USE(X86_REG_YMM9) \
	X86_REG_USE(X86_REG_YMM10) \
	X86_REG_USE(X86_REG_YMM11) \
	X86_REG_USE(X86_REG_YMM12) \
	X86_REG_USE(X86_REG_YMM13) \
	X86_REG_USE(X86_REG_YMM14) \
	X86_REG_USE(X86_REG_YMM15) \
	X86_REG_USE(X86_REG_YMM16) \
	X86_REG_USE(X86_REG_YMM17) \
	X86_REG_USE(X86_REG_YMM18) \
	X86_REG_USE(X86_REG_YMM19) \
	X86_REG_USE(X86_REG_YMM20) \
	X86_REG_USE(X86_REG_YMM21) \
	X86_REG_USE(X86_REG_YMM22) \
	X86_REG_USE(X86_REG_YMM23) \
	X86_REG_USE(X86_REG_YMM24) \
	X86_REG_USE(X86_REG_YMM25) \
	X86_REG_USE(X86_REG_YMM26) \
	X86_REG_USE(X86_REG_YMM27) \
	X86_REG_USE(X86_REG_YMM28) \
	X86_REG_USE(X86_REG_YMM29) \
	X86_REG_USE(X86_REG_YMM30) \
	X86_REG_USE(X86_REG_YMM31) \
	X86_REG_USE(X86_REG_ZMM0) \
	X86_REG_USE(X86_REG_ZMM1) \
	X86_REG_USE(X86_REG_ZMM2) \
	X86_REG_USE(X86_REG_ZMM3) \
	X86_REG_USE(X86_REG_ZMM4) \
	X86_REG_USE(X86_REG_ZMM5) \
	X86_REG_USE(X86_REG_ZMM6) \
	X86_REG_USE(X86_REG_ZMM7) \
	X86_REG_USE(X86_REG_ZMM8) \
	X86_REG_USE(X86_REG_ZMM9) \
	X86_REG_USE(X86_REG_ZMM10) \
	X86_REG_USE(X86_REG_ZMM11) \
	X86_REG_USE(X86_REG_ZMM12) \
	X86_REG_USE(X86_REG_ZMM13) \
	X86_REG_USE(X86_REG_ZMM14) \
	X86_REG_USE(X86_REG_ZMM15) \
	X86_REG_USE(X86_REG_ZMM16) \
	X86_REG_USE(X86_REG_ZMM17) \
	X86_REG_USE(X86_REG_ZMM18) \
	X86_REG_USE(X86_REG_ZMM19) \
	X86_REG_USE(X86_REG_ZMM20) \
	X86_REG_USE(X86_REG_ZMM21) \
	X86_REG_USE(X86_REG_ZMM22) \
	X86_REG_USE(X86_REG_ZMM23) \
	X86_REG_USE(X86_REG_ZMM24) \
	X86_REG_USE(X86_REG_ZMM25) \
	X86_REG_USE(X86_REG_ZMM26) \
	X86_REG_USE(X86_REG_ZMM27) \
	X86_REG_USE(X86_REG_ZMM28) \
	X86_REG_USE(X86_REG_ZMM29) \
	X86_REG_USE(X86_REG_ZMM30) \
	X86_REG_USE(X86_REG_ZMM31) \
	X86_REG_USE(X86_REG_R8B) \
	X86_REG_USE(X86_REG_R9B) \
	X86_REG_USE(X86_REG_R10B) \
	X86_REG_USE(X86_REG_R11B) \
	X86_REG_USE(X86_REG_R12B) \
	X86_REG_USE(X86_REG_R13B) \
	X86_REG_USE(X86_REG_R14B) \
	X86_REG_USE(X86_REG_R15B) \
	X86_REG_USE(X86_REG_R8D) \
	X86_REG_USE(X86_REG_R9D) \
	X86_REG_USE(X86_REG_R10D) \
	X86_REG_USE(X86_REG_R11D) \
	X86_REG_USE(X86_REG_R12D) \
	X86_REG_USE(X86_REG_R13D) \
	X86_REG_USE(X86_REG_R14D) \
	X86_REG_USE(X86_REG_R15D) \
	X86_REG_USE(X86_REG_R8W) \
	X86_REG_USE(X86_REG_R9W) \
	X86_REG_USE(X86_REG_R10W) \
	X86_REG_USE(X86_REG_R11W) \
	X86_REG_USE(X86_REG_R12W) \
	X86_REG_USE(X86_REG_R13W) \
	X86_REG_USE(X86_REG_R14W) \
	X86_REG_USE(X86_REG_R15W) \
	X86_REG_USE(X86_REG_BND0) \
	X86_REG_USE(X86_REG_BND1) \
	X86_REG_USE(X86_REG_BND2) \
	X86_REG_USE(X86_REG_BND3) \


const char * ROP::InstructionConverter::convertCapstoneRegIdToString(x86_reg regId) {
    #define X86_REG_USE(REG) case REG: { return #REG; }

    switch (regId) {
        X86_REG_LIST
        case X86_REG_INVALID: case X86_REG_ENDING: {
            break;
        }
    }

    #undef X86_REG_USE

    return "N/A";
}

const char * ROP::InstructionConverter::convertCapstoneRegIdToShortString(x86_reg regId) {
    // Get a string like "X86_REG_RAX".
    const char *regCString = InstructionConverter::convertCapstoneRegIdToString(regId);

    if (strcmp(regCString, "N/A") == 0) {
        return regCString;
    }

    // Keep only the part after the last '_' (e.g. just "RAX").
    regCString = strrchr(regCString, '_') + 1;

    return regCString;
}

x86_reg ROP::InstructionConverter::convertRegShortStringToCapstoneRegId(std::string regString) {
    // Convert regString to upper case.
    for (char& currChar : regString) {
        currChar = toupper(currChar);
    }

    regString = "X86_REG_" + regString;

    #define X86_REG_USE(REG) if (regString == #REG) { return REG; }
    X86_REG_LIST
    #undef X86_REG_USE

    return X86_REG_INVALID;
}

#pragma endregion Static methods
