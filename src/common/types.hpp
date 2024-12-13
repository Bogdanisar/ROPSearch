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
        static const int MaxInstructionBytesCount = 24;
        static const int MaxInstructionSequenceSize = 10;
        static const bool architectureIsLittleEndian = true;
        static const AssemblySyntax InstructionASMSyntax = AssemblySyntax::Intel;
    };
}


#endif // TYPES_H
