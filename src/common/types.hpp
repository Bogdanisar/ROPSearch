#ifndef TYPES_H
#define TYPES_H

#include <vector>


namespace ROP {
    using byte = unsigned char;
    using byteSequence = std::vector<byte>;

    enum class AssemblySyntax {
        Intel, // The assembly instructions are written in Intel syntax.
        ATT, // The assembly instructions are written in AT&T syntax.
    };

    struct ROPConsts {
        /** Maximum possible number of bytes in an x86 instruction. */
        static const int MaxInstructionBytesCount = 24;
        static const bool architectureIsLittleEndian = true;
    };
}


#endif // TYPES_H
