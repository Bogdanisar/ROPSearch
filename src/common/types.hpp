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

    enum class AssemblySyntax {
        Intel, // The assembly instructions are written in Intel syntax.
        ATT, // The assembly instructions are written in AT&T syntax.
    };

}


#endif // TYPES_H
