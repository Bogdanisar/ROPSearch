#ifndef BYTE_PARSING_X86_H
#define BYTE_PARSING_X86_H

#include <cassert>
#include <optional>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"


#pragma region Prefix, REX bytes
#if false
int ________Prefix_REX_bytes________;
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

struct PrefixBytesInfo {
    // The last parsed byte from legacy prefix group 1 (0xF0, 0xF2, 0xF3)
    // or 0 if not present.
    ROP::byte group1Byte = 0;

    // The last parsed byte from legacy prefix group 2 (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65)
    // or 0 if not present.
    ROP::byte group2Byte = 0;

    // The last parsed byte from legacy prefix group 3 (0x66)
    // or 0 if not present.
    ROP::byte group3Byte = 0;

    // The last parsed byte from legacy prefix group 4 (0x67)
    // or 0 if not present.
    ROP::byte group4Byte = 0;

    // The last REX byte that was parsed, that is not followed by other prefix bytes or another REX byte.
    // Or 0 if not present.
    ROP::byte rexByte = 0;
};

// Update the given prefix bytes info with a new prefix byte.
static inline std::optional<PrefixBytesInfo> ParsePrefixByte(
    PrefixBytesInfo info, ROP::byte byte, ROP::BitSizeClass archSize
) {
    switch (byte) {
        // - Legacy prefix bytes belong to different prefix groups;
        // - At most one byte from the each group can be used for an instruction.
        // - Only the last-parsed prefix byte in each group is used;
        // https://wiki.osdev.org/X86-64_Instruction_Encoding#Legacy_Prefixes
        case 0xF0: case 0xF2: case 0xF3: {
            info.group1Byte = byte;
            info.rexByte = 0;
            return info;
        }
        case 0x26: case 0x2E: case 0x36: case 0x3E: case 0x64: case 0x65:  {
            info.group2Byte = byte;
            info.rexByte = 0;
            return info;
        }
        case 0x66: {
            info.group3Byte = 0x66;
            info.rexByte = 0;
            return info;
        }
        case 0x67: {
            info.group4Byte = 0x67;
            info.rexByte = 0;
            return info;
        }

        // On x64, REX prefix bytes are always parsed but only the last REX byte is active
        // and only if it isn't followed by prefix legacy bytes;
        // https://intelxed.github.io/ref-manual/
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4a: case 0x4b:
        case 0x4c: case 0x4d: case 0x4e: case 0x4f: {
            if (archSize == ROP::BitSizeClass::BIT64) {
                info.rexByte = byte;
                return info;
            }
            break;
        }
    }

    return std::nullopt;
}

#pragma endregion Prefix, REX bytes


#pragma region ModRM bytes
#if false
int ________ModRM_bytes________;
#endif

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

#pragma endregion ModRM bytes


#pragma region Returns
#if false
int ________Returns________;
#endif

static inline bool BytesAreNearRetInstruction(const ROP::byte *bytes,
                                              const unsigned numBytes,
                                              const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    // "ret" instruction.
    if (numBytes == 1 && bytes[0] == 0xC3) { return true; }

    // "ret imm16" instruction.
    if (numBytes == 3 && bytes[0] == 0xC2) { return true; }

    return false;
}

static inline bool BytesAreFarRetInstruction(const ROP::byte *bytes,
                                             const unsigned numBytes,
                                             const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    // "retf" instruction.
    if (numBytes == 1 && bytes[0] == 0xCB) { return true; }

    // "retf imm16" instruction.
    if (numBytes == 3 && bytes[0] == 0xCA) { return true; }

    return false;
}

#pragma endregion Returns


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
static inline bool BytesAreDirectRelativeJmpInstruction32bit(const ROP::byte *bytes,
                                                             const unsigned numBytes,
                                                             const PrefixBytesInfo& prefixes,
                                                             int32_t *offset = NULL) {
    assert(numBytes > 0);

    if (numBytes == (1 + 1) && bytes[0] == 0xEB) {
        // Is "JMP rel8" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int8_t>(bytes + 1);
        }
        return true;
    }

    bool hasSizeOverridePrefix = (prefixes.group3Byte == (ROP::byte)ROP::PrefixByteX86::OPERAND_SIZE_OVERRIDE);
    if (!hasSizeOverridePrefix && numBytes == (1 + 4) && bytes[0] == 0xE9) {
        // Is "JMP rel32" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int32_t>(bytes + 1);
        }
        return true;
    }

    if (hasSizeOverridePrefix && numBytes == (1 + 2) && bytes[0] == 0xE9) {
        // Is "JMP rel16" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int16_t>(bytes + 1);
        }
        return true;
    }

    return false;
}

/**
 * The same as `BytesAreDirectRelativeJmpInstruction32bit()`,
 * but try parsing the prefix bytes as well.
 */
static inline bool BytesAreDirectRelativeJmpInstruction32bitWithPrefixParse(const ROP::byte *bytes,
                                                                            const unsigned numBytes,
                                                                            const PrefixBytesInfo& prefixes,
                                                                            int32_t *offset = NULL) {
    assert(numBytes > 0);

    // Try to parse a prefix byte.
    if (numBytes >= 2) {
        std::optional<PrefixBytesInfo> newPref = ParsePrefixByte(prefixes, bytes[0], ROP::BitSizeClass::BIT32);
        if (newPref && BytesAreDirectRelativeJmpInstruction32bitWithPrefixParse(bytes + 1,
                                                                                numBytes - 1,
                                                                                *newPref,
                                                                                offset)) {
            return true;
        }
    }

    if (BytesAreDirectRelativeJmpInstruction32bit(bytes, numBytes, prefixes, offset)) {
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
static inline bool BytesAreDirectRelativeJmpInstruction64bit(const ROP::byte *bytes,
                                                             const unsigned numBytes,
                                                             const PrefixBytesInfo& prefixes,
                                                             int32_t *offset = NULL) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    if (numBytes == (1 + 1) && bytes[0] == 0xEB) {
        // Is "JMP rel8" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int8_t>(bytes + 1);
        }
        return true;
    }

    // The operand-size override prefix byte doesn't affect this instruction on x64,
    // so the "JMP rel16" instruction is not possible on 64bit.

    if (numBytes == (1 + 4) && bytes[0] == 0xE9) {
        // Is "JMP rel32" instruction.
        if (offset) {
            *offset = ConvertLittleEndianBytesToInteger<int32_t>(bytes + 1);
        }
        return true;
    }

    return false;
}

/**
 * The same as `BytesAreDirectRelativeJmpInstruction64bit()`,
 * but try parsing the prefix bytes as well.
 */
static inline bool BytesAreDirectRelativeJmpInstruction64bitWithPrefixParse(const ROP::byte *bytes,
                                                                            const unsigned numBytes,
                                                                            const PrefixBytesInfo& prefixes,
                                                                            int32_t *offset = NULL) {
    assert(numBytes > 0);

    // Try to parse a prefix byte.
    if (numBytes >= 2) {
        std::optional<PrefixBytesInfo> newPref = ParsePrefixByte(prefixes, bytes[0], ROP::BitSizeClass::BIT64);
        if (newPref && BytesAreDirectRelativeJmpInstruction64bitWithPrefixParse(bytes + 1,
                                                                                numBytes - 1,
                                                                                *newPref,
                                                                                offset)) {
            return true;
        }
    }

    if (BytesAreDirectRelativeJmpInstruction64bit(bytes, numBytes, prefixes, offset)) {
        return true;
    }

    return false;
}

/**
 * Check if this is an absolute "jmp" instruction ("absolute" meaning "RIP = newAddress").
 * In other words, check if this is a "JMP ptr16:16" or "JMP ptr16:32" instruction.
 * This instruction type seems to be valid on x86_32, but not x86_64.
 */
static inline bool BytesAreDirectAbsoluteJmpInstruction32bit(const ROP::byte *bytes,
                                                             const unsigned numBytes,
                                                             const PrefixBytesInfo& prefixes) {
    assert(numBytes > 0);
    bool hasSizeOverridePrefix = (prefixes.group3Byte == (ROP::byte)ROP::PrefixByteX86::OPERAND_SIZE_OVERRIDE);

    if (!hasSizeOverridePrefix && numBytes == (1 + 2 + 4) && bytes[0] == 0xEA) {
        // Is "JMP ptr16:32" instruction.
        return true;
    }

    if (hasSizeOverridePrefix && numBytes == (1 + 2 + 2) && bytes[0] == 0xEA) {
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
static inline bool BytesAreNearAbsoluteIndirectJmpInstructionOrInvalid(const ROP::byte *bytes,
                                                                       const unsigned numBytes,
                                                                       const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    // Opcode: 0xFF /4.
    if (numBytes >= 2 && bytes[0] == 0xFF && GetRegBitsOfModRMByte(bytes[1]) == 4) {
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
static inline bool BytesAreFarAbsoluteIndirectJmpInstructionOrInvalid(const ROP::byte *bytes,
                                                                      const unsigned numBytes,
                                                                      const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    // Opcode: 0xFF /5.
    if (numBytes >= 2 && bytes[0] == 0xFF && GetRegBitsOfModRMByte(bytes[1]) == 5) {
        return true;
    }

    return false;
}

#pragma endregion Unconditional indirect JMPs


#pragma region Software interrupts
#if false
int ________Software_interrupts________;
#endif

/**
 * Check if this is an "int 0x80" instruction,
 * which can be used to make system calls on 32bit/64bit Linux (only through the 32bit ABI).
 */
static inline bool BytesAreSystemCallInterruptInstruction(const ROP::byte *bytes,
                                                          const unsigned numBytes,
                                                          const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    // "int 0x80" instruction.
    return (numBytes == 2 && bytes[0] == 0xCD && bytes[1] == 0x80);
}

/** Check if this is a (software) interrupt instruction. */
static inline bool BytesAreInterruptInstruction(const ROP::byte *bytes,
                                                const unsigned numBytes,
                                                const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);

    // "int3" instruction.
    if (numBytes == 1 && bytes[0] == 0xCC) { return true; }

    // "int imm8".
    if (numBytes == 2 && bytes[0] == 0xCD) { return true; }

    // "into" instruction.
    if (numBytes == 1 && bytes[0] == 0xCE) { return true; }

    // "int1" instruction.
    if (numBytes == 1 && bytes[0] == 0xF1) { return true; }

    return false;
}

#pragma endregion Software interrupts


#pragma region Call instructions
#if false
int ________Call_instructions________;
#endif

/**
 * Check if this is a relative "call" instruction ("relative" meaning "RIP = RIP + offset").
 * @note As an asm string, this is represented as "call finalAddress",
 *       even though only the offset is encoded.
 */
static inline bool BytesAreRelativeCallInstruction64bit(const ROP::byte *bytes,
                                                        const unsigned numBytes,
                                                        const PrefixBytesInfo& prefixes) {
    UNUSED(prefixes);
    assert(numBytes > 0);
    return (numBytes == 5 && bytes[0] == 0xE8);
}

#pragma endregion Call instructions


#pragma region High level
#if false
int ________High_level________;
#endif

/**
 * Check if the given bytes represent an instruction
 * that is useful as the ending instruction of an instruction sequence.
 */
static inline bool BytesAreUsefulInstructionAtSequenceEnd(const ROP::byte *bytes,
                                                          const unsigned numBytes,
                                                          const PrefixBytesInfo& prefixes,
                                                          ROP::BitSizeClass archSize) {
    assert(numBytes > 0);

    // Try to parse a prefix byte.
    if (numBytes >= 2) {
        std::optional<PrefixBytesInfo> newPref = ParsePrefixByte(prefixes, bytes[0], archSize);
        if (newPref && BytesAreUsefulInstructionAtSequenceEnd(bytes + 1, numBytes - 1, *newPref, archSize)) {
            return true;
        }
    }

    if (BytesAreNearRetInstruction(bytes, numBytes, prefixes)) {
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
static inline bool BytesAreBadInstructionInsideSequence(const ROP::byte *bytes,
                                                        const unsigned numBytes,
                                                        const PrefixBytesInfo& prefixes,
                                                        ROP::BitSizeClass archSize) {
    assert(numBytes > 0);

    // Try to parse a prefix byte.
    if (numBytes >= 2) {
        std::optional<PrefixBytesInfo> newPref = ParsePrefixByte(prefixes, bytes[0], archSize);
        if (newPref && BytesAreBadInstructionInsideSequence(bytes + 1, numBytes - 1, *newPref, archSize)) {
            return true;
        }
    }

    if (BytesAreNearRetInstruction(bytes, numBytes, prefixes)) {
        return true;
    }
    if (BytesAreFarRetInstruction(bytes, numBytes, prefixes)) {
        return true;
    }

    if (archSize == ROP::BitSizeClass::BIT32
        && BytesAreDirectRelativeJmpInstruction32bit(bytes, numBytes, prefixes)) {
        return true;
    }
    if (archSize == ROP::BitSizeClass::BIT64
        && BytesAreDirectRelativeJmpInstruction64bit(bytes, numBytes, prefixes)) {
        return true;
    }

    if (archSize == ROP::BitSizeClass::BIT32
        && BytesAreDirectAbsoluteJmpInstruction32bit(bytes, numBytes, prefixes)) {
        return true;
    }

    if (BytesAreNearAbsoluteIndirectJmpInstructionOrInvalid(bytes, numBytes, prefixes)) {
        return true;
    }
    if (BytesAreFarAbsoluteIndirectJmpInstructionOrInvalid(bytes, numBytes, prefixes)) {
        return true;
    }

    if (BytesAreInterruptInstruction(bytes, numBytes, prefixes)
        && !BytesAreSystemCallInterruptInstruction(bytes, numBytes, prefixes) // syscalls may be useful inside a sequence.
    ) {
        return true;
    }

    if (BytesAreRelativeCallInstruction64bit(bytes, numBytes, prefixes)) {
        return true;
    }

    // TODO: Add more

    return false;
}

#pragma endregion High level


#endif // BYTE_PARSING_X86_H
