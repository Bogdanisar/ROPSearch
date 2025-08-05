#ifndef BYTE_PARSING_X86_H
#define BYTE_PARSING_X86_H

#include <cassert>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"


#pragma region Prefix, REX, ModRM bytes
#if false
int ________Prefix_REX_ModRM_bytes________;
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

static inline unsigned GetModBitsOfModRMByte(ROP::byte b) {
    // Most significant 2 bits.
    return (b >> 6) & 0b11;
}
static inline unsigned GetRegBitsOfModRMByte(ROP::byte b) {
    // Middle 3 bits;
    return (b >> 3) & 0b111;
}
static inline unsigned GetRMBitsOfModRMByte(ROP::byte b) {
    // Least significant 3 bits;
    return b & 0b111;
}

#pragma endregion Prefix, REX, ModRM bytes


#pragma region Unconditional direct JMPs
#if false
int ________Unconditional_direct_JMPs________;
#endif

// Either unconditional direct relative jumps (RIP-relative offset is hardcoded in instruction bytes)
// or unconditional direct absolute jumps (new RIP absolute address is hardcoded in instruction bytes).


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

#pragma endregion Unconditional direct JMPs


#pragma region Unconditional indirect JMPs
#if false
int ________Unconditional_indirect_JMPs________;
#endif

/**
 * Check if the bytes are a near, absolute indirect "jmp" instruction,
 * i.e. "JMP r/m16", "JMP r/m32" or "JMP r/m64".
 * @return `false`, if the bytes definitely don't match this instruction type.
 *         `true`, if the bytes match this instruction type or are invalid.
 */
static inline bool BytesAreNearAbsoluteIndirectJmpInstructionOrInvalid(const ROP::byteSequence& bSeq,
                                                                       int first, int last) {
    const int numBytes = (last - first + 1);

    // Opcode: 0xFF /4.
    if (numBytes >= 2 && bSeq[first] == 0xFF && GetRegBitsOfModRMByte(bSeq[first + 1]) == 4) {
        return true;
    }

    // Preceded by REX byte.
    if (numBytes >= 3 && ByteIsValidRexByte(bSeq[first])
        && BytesAreNearAbsoluteIndirectJmpInstructionOrInvalid(bSeq, first + 1, last)) {
        return true;
    }

    return false;
}

/**
 * Check if the bytes are a far, absolute indirect "jmp" instruction,
 * i.e. "JMP m16:16", "JMP m16:32" or "JMP m16:64".
 * @return `false`, if the bytes definitely don't match this instruction type.
 *         `true`, if the bytes match this instruction type or are invalid.
 */
static inline bool BytesAreFarAbsoluteIndirectJmpInstructionOrInvalid(const ROP::byteSequence& bSeq,
                                                                      int first, int last) {
    const int numBytes = (last - first + 1);

    // Opcode: 0xFF /5.
    if (numBytes >= 2 && bSeq[first] == 0xFF && GetRegBitsOfModRMByte(bSeq[first + 1]) == 5) {
        return true;
    }

    // Preceded by REX byte.
    if (numBytes >= 3 && ByteIsValidRexByte(bSeq[first])
        && BytesAreFarAbsoluteIndirectJmpInstructionOrInvalid(bSeq, first + 1, last)) {
        return true;
    }

    return false;
}

#pragma endregion Unconditional indirect JMPs


#pragma region Misc
#if false
int ________Misc________;
#endif

/**
 * Check if this is a relative "call" instruction ("relative" meaning "RIP = RIP + offset").
 * @note As an asm string, this is represented as "call finalAddress",
 *       even though only the offset is encoded.
 */
static inline bool BytesAreRelativeCallInstruction64bit(const ROP::byteSequence& bSeq, int first, int last) {
    const int numBytes = (last - first + 1);
    return (numBytes == 5 && bSeq[first] == 0xE8);
}

static inline bool BytesAreNearRetInstruction(const ROP::byteSequence& bSeq, int first, int last) {
    const int numBytes = (last - first + 1);

    // "ret" instruction.
    if (numBytes == 1 && bSeq[first] == 0xC3) { return true; }

    // "ret imm16" instruction.
    if (numBytes == 3 && bSeq[first] == 0xC2) { return true; }

    return false;
}

static inline bool BytesAreFarRetInstruction(const ROP::byteSequence& bSeq, int first, int last) {
    const int numBytes = (last - first + 1);

    // "retf" instruction.
    if (numBytes == 1 && bSeq[first] == 0xCB) { return true; }

    // "retf imm16" instruction.
    if (numBytes == 3 && bSeq[first] == 0xCA) { return true; }

    return false;
}

#pragma endregion Misc


#pragma region High level
#if false
int ________High_level________;
#endif

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

    if (BytesAreNearRetInstruction(bSeq, first, last)) {
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

    if (BytesAreNearRetInstruction(bSeq, first, last)) {
        return true;
    }
    if (BytesAreFarRetInstruction(bSeq, first, last)) {
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

    if (BytesAreNearAbsoluteIndirectJmpInstructionOrInvalid(bSeq, first, last)) {
        return true;
    }
    if (BytesAreFarAbsoluteIndirectJmpInstructionOrInvalid(bSeq, first, last)) {
        return true;
    }

    // TODO: Add more

    return false;
}

#pragma endregion High level


#endif // BYTE_PARSING_X86_H
