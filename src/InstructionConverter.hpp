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

        /**
         * Convert instructions (assembly strings) to a byte sequence.
         * @param instructionSequenceAsm The assemby strings. Multiple instructions can be separated by ";".
         * @param asmSyntax The assembly syntax of the input instruction string.
         * @param addr The virtual memory address of the first instruction.
         *             This might influence the output for some instructions.
         * @return The converted instruction sequence and the number of parsed instructions.
         * @warning A trailing ";" in the asm is counted as an additional instruction.
         */
        std::pair<byteSequence, unsigned>
        convertInstructionSequenceToBytes(std::string instructionSequenceAsm,
                                          AssemblySyntax asmSyntax,
                                          unsigned long long addr = 0);

        /**
         * Converts / disassembles a sequence of bytes to instructions (as assembly strings).
         * The number of disassembled bytes might be smaller than the size of the input
         * if asked or if there's a parsing error.
         * @param instrSeqBytes The input byte sequence.
         * @param instrSeqBytesCount The byte count of the input byte sequence.
         * @param asmSyntax The desired syntax for the output assembly string.
         * @param addr The virtual memory address of the first byte.
         *             This might affect the output string of some instructions.
         * @param parseCount The max number of output instructions to parse or 0 to disassemble all input bytes.
         * @return The converted instructions (as strings) and the number of disassembled bytes.
         */
        std::pair<std::vector<std::string>, unsigned>
        convertInstructionSequenceToString(const byte * const instrSeqBytes,
                                           const size_t instrSeqBytesCount,
                                           AssemblySyntax asmSyntax,
                                           unsigned long long addr = 0,
                                           const size_t parseCount = 0);

        /**
         * Converts / disassembles a sequence of bytes to instructions (as assembly strings).
         * The number of disassembled bytes might be smaller than the size of the input
         * if asked or if there's a parsing error.
         * @param instructionSequence The input byte sequence.
         * @param asmSyntax The desired syntax for the output assembly string.
         * @param addr The virtual memory address of the first byte.
         *             This might affect the output string of some instructions.
         * @param parseCount The max number of output instructions to parse or 0 to disassemble all input bytes.
         * @return The converted instructions (as strings) and the number of disassembled bytes.
         */
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

        /**
         * Concatenates instructions with "; " between them.
         */
        std::string
        concatenateInstructionsAsm(std::vector<std::string> instructionsAsm);

        ~InstructionConverter();
    };

}


#endif // INSTRUCTION_CONVERTER_H
