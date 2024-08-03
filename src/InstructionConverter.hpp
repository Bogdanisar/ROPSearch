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

        // Returns { The converted instructions (as strings); The number of disassembled bytes };
        // The syntax of the returned instructions is given in the second argument.
        // The number of disassembled bytes will be smaller than the size of the input if there's a parsing error.
        static std::pair<std::vector<std::string>, unsigned>
        convertInstructionSequenceToString(const byte * const instrSeqBytes, const size_t instrSeqBytesCount, AssemblySyntax asmSyntax);

        // Returns { The converted instructions (as strings); The number of disassembled bytes };
        // The syntax of the returned instructions is given in the second argument.
        // The number of disassembled bytes will be smaller than the size of the input if there's a parsing error.
        static std::pair<std::vector<std::string>, unsigned>
        convertInstructionSequenceToString(byteSequence instructionSequence, AssemblySyntax asmSyntax);

        // Takes instruction(s) given as strings
        // and normalizes them according to the same syntax we use internally in ROOP.
        // - The first argument may contain multiple instructions separated by ";".
        // - The syntax of the input instructions is given in the second argument.
        static std::vector<std::string>
        normalizeInstructionAsm(std::string origInsSequenceAsm, AssemblySyntax inputAsmSyntax);

        // Concatenates instructions with "; " between them.
        static std::string
        concatenateInstructionsAsm(std::vector<std::string> instructionsAsm);
    };

}


#endif // INSTRUCTION_CONVERTER_H
