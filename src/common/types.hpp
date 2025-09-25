#ifndef TYPES_H
#define TYPES_H

#include <vector>


namespace ROP {

    struct ROPConsts {
        /** Maximum possible number of bytes in an x86 instruction. */
        static const int MaxInstructionBytesCount = 24;
        static const bool architectureIsLittleEndian = true;
    };

    using byte = unsigned char;
    using byteSequence = std::vector<byte>;

    // "unsigned long long" is at least 64 bits, as per the C++ docs.
    using addressType = unsigned long long;

    enum class BitSizeClass {
        BIT32 = 1, // (same int value as ELFCLASS32 from <elf.h>)
        BIT64 = 2, // (same int value as ELFCLASS64 from <elf.h>)
    };

    enum class AssemblySyntax {
        Intel, // The assembly instructions are written in Intel syntax.
        ATT, // The assembly instructions are written in AT&T syntax.
    };

    enum class PrefixByteX86 {
        // No prefix byte.
        NONE = 0,

        // LOCK prefix
        LOCK = 0xF0,

        // REPNE/REPNZ prefix
        REPNE = 0xF2,
        REPNZ = 0xF2,

        // REP or REPE/REPZ prefix
        REP = 0xF3,
        REPE = 0xF3,
        REPZ = 0xF3,

        // CS segment override / Branch not taken
        CS_SEGMENT_OVERRIDE = 0x2E,
        BRANCH_NOT_TAKEN = 0x2E,

        // SS segment override
        SS_SEGMENT_OVERRIDE = 0x36,

        // DS segment override / Branch taken
        DS_SEGMENT_OVERRIDE = 0x3E,
        BRANCH_TAKEN = 0x3E,

        // ES segment override
        ES_SEGMENT_OVERRIDE = 0x26,

        // FS segment override
        FS_SEGMENT_OVERRIDE = 0x64,

        // GS segment override
        GS_SEGMENT_OVERRIDE = 0x65,

        // Operand-size override prefix
        OPERAND_SIZE_OVERRIDE = 0x66,

        // Address-size override prefix
        ADDRESS_SIZE_OVERRIDE = 0x67,
    };
}


#endif // TYPES_H
