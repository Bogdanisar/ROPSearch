#ifndef INSTRUCTION_CONVERTER_H
#define INSTRUCTION_CONVERTER_H

#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include "common/types.hpp"
#include "common/utils.hpp"


namespace ROP {

    class InstructionConverter {
        // Inner assembler framework;
        ks_engine *ksEngine;
        AssemblySyntax ksEngineSyntax;

        void initKeystone();

        // Inner disassembler framework;
        csh capstoneHandle;
        AssemblySyntax csHandleSyntax;

        void initCapstone();

        public:
        InstructionConverter();

        // Returns the converted instruction sequence and the number of parsed instructions.
        // Note: A trailing ";" in the asm is counted as an additional instruction.
        // "addr": The virtual memory address of the first instruction. This can influence the output for some instructions.
        std::pair<byteSequence, unsigned>
        convertInstructionSequenceToBytes(std::string instructionSequenceAsm,
                                          AssemblySyntax asmSyntax,
                                          unsigned long long addr = 0);

        // Returns { The converted instructions (as strings); The number of disassembled bytes };
        // The syntax of the returned instructions is given in the second argument.
        // The number of disassembled bytes will be smaller than the size of the input if there's a parsing error.
        // "addr": The virtual memory address of the first byte. This can influence the output for some instructions.
        // "parseCount": The maximum number of assembly instructions to parse from the bytes. Pass "0" for "all of them".
        std::pair<std::vector<std::string>, unsigned>
        convertInstructionSequenceToString(const byte * const instrSeqBytes,
                                           const size_t instrSeqBytesCount,
                                           AssemblySyntax asmSyntax,
                                           unsigned long long addr = 0,
                                           const size_t parseCount = 0);

        // Returns { The converted instructions (as strings); The number of disassembled bytes };
        // The syntax of the returned instructions is given in the second argument.
        // The number of disassembled bytes will be smaller than the size of the input if there's a parsing error.
        // "addr": The virtual memory address of the first byte. This can influence the output for some instructions.
        // "parseCount": The maximum number of assembly instructions to parse from the bytes. Pass "0" for "all of them".
        std::pair<std::vector<std::string>, unsigned>
        convertInstructionSequenceToString(byteSequence instructionSequence,
                                           AssemblySyntax asmSyntax,
                                           unsigned long long addr = 0,
                                           const size_t parseCount = 0);

        /**
         * Takes the input instruction(s) and normalizes them according to the required syntax.
         * @param origInsSequenceAsm The instruction(s), given in assembly, as a string. Multiple instructions are separated by ";".
         * @param inputAsmSyntax The assembly syntax of `origInsSequenceAsm`.
         * @param outputAsmSyntax The desired assembly syntax of the returned instructions.
         */
        std::vector<std::string>
        normalizeInstructionAsm(std::string origInsSequenceAsm, AssemblySyntax inputAsmSyntax, AssemblySyntax outputAsmSyntax);

        // Concatenates instructions with "; " between them.
        std::string
        concatenateInstructionsAsm(std::vector<std::string> instructionsAsm);

        ~InstructionConverter();
    };

}


#endif // INSTRUCTION_CONVERTER_H
