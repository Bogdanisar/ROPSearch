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
        LOCK = 1<<1,

        // REPNE/REPNZ prefix
        REPNE = 1<<2,
        REPNZ = 1<<2,

        // REP or REPE/REPZ prefix
        REP = 1<<3,
        REPE = 1<<3,
        REPZ = 1<<3,

        // CS segment override / Branch not taken
        CS_SEGMENT_OVERRIDE = 1<<4,
        BRANCH_NOT_TAKEN = 1<<4,

        // SS segment override
        SS_SEGMENT_OVERRIDE = 1<<5,

        // DS segment override / Branch taken
        DS_SEGMENT_OVERRIDE = 1<<6,
        BRANCH_TAKEN = 1<<6,

        // ES segment override
        ES_SEGMENT_OVERRIDE = 1<<7,

        // FS segment override
        FS_SEGMENT_OVERRIDE = 1<<8,

        // GS segment override
        GS_SEGMENT_OVERRIDE = 1<<9,

        // Operand-size override prefix
        OPERAND_SIZE_OVERRIDE = 1<<10,

        // Address-size override prefix
        ADDRESS_SIZE_OVERRIDE = 1<<11,
    };
}


#endif // TYPES_H
