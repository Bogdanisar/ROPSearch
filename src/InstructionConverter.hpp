#ifndef INSTRUCTION_CONVERTER_H
#define INSTRUCTION_CONVERTER_H

#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"


namespace ROOP {

    class InstructionConverter {
        public:

        // Returns the converted instruction sequence and the number of parsed instructions.
        // Note: A trailing ";" in the asm is counted as an additional instruction.
        static std::pair<byteSequence, unsigned>
        convertInstructionSequenceToBytes(std::string instructionSequenceAsm, AssemblySyntax asmSyntax);

        // Returns the converted instructions, as strings;
        // The syntax of the returned instructions is given in the second argument.
        static std::vector<std::string>
        convertInstructionSequenceToString(byteSequence instructionSequence, AssemblySyntax asmSyntax);
    };

}


#endif // INSTRUCTION_CONVERTER_H
