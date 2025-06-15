#ifndef INSTRUCTION_CONVERTER_H
#define INSTRUCTION_CONVERTER_H

#include <bitset>
#include <vector>

#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include "common/types.hpp"
#include "common/utils.hpp"


namespace ROP {

    /**
     * Class that stores details for a given x86 instruction,
     * such as read/write access of registers.
     */
    struct RegisterInfo {
        // Registers that are read by the instruction (see "x86_reg" enum).
        std::bitset<X86_REG_ENDING> rRegs;

        // Registers that are written by the instruction (see "x86_reg" enum).
        std::bitset<X86_REG_ENDING> wRegs;

        // If the instruction reads from a memory operand (e.g. [rax + 0xf]).
        bool readsMemoryOperand;
        // If the instruction writes to a memory operand (e.g. [rax + 0xf]).
        bool writesMemoryOperand;

        // If the instruction contains an immediate value (e.g. "mov rax, 0x10").
        bool hasImmediateValue;

        static RegisterInfo reduceRegInfoListWithAndOperator(const std::vector<RegisterInfo> &infoList);
        static RegisterInfo reduceRegInfoListWithOrOperator(const std::vector<RegisterInfo> &infoList);
    };

    class InstructionConverter {
        // Inner assembler framework;
        ks_engine *ksEngine;
        AssemblySyntax ksEngineSyntax;

        void initKeystone();

        // Inner disassembler framework;
        csh capstoneHandle;
        AssemblySyntax csHandleSyntax;
        bool csHandleDetailModeEnabled;

        void initCapstone();

        //
        /**
         * Adjust the Capstone handle (if needed) to use Intel or AT&T syntax.
         * @return `true` if the setting was changed, `false` if there was an error.
         */
        inline bool updateCapstoneAssemblySetting(AssemblySyntax newAsmSyntax);

        //
        /**
         * Adjust the Capstone handle (if needed) to enable/disable DETAIL mode.
         * @return `true` if the setting was changed, `false` if there was an error.
         */
        inline bool updateCapstoneDetailSetting(bool detailsEnabled);

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
                                          addressType addr = 0);

        /**
         * Converts / disassembles a sequence of bytes into instructions (as assembly strings).
         * The number of disassembled bytes might be smaller than the size of the input
         * if asked or if there's a parsing error.
         * @param instrSeqBytes The input byte sequence.
         * @param instrSeqBytesCount The byte count of the input byte sequence.
         * @param asmSyntax The desired syntax for the output assembly string.
         * @param addr The virtual memory address of the first byte. This might
         *             affect the output string of some instructions. Use 0 otherwise.
         * @param parseCount The max number of output instructions to parse or 0 to disassemble all input bytes.
         * @param outInstructionAsm The assembly strings of the instructions decoded from the input bytes.
         * @param outRegInfo Register information for each decoded instruction, if desired. Can be NULL.
         *                   Note: Getting the register info might imply a performance overhead.
         *
         * @return The number of disassembled bytes. Will be 0 if invalid input or error.
         */
        unsigned
        convertInstructionSequenceToString(const byte * const instrSeqBytes,
                                           const size_t instrSeqBytesCount,
                                           AssemblySyntax asmSyntax,
                                           addressType addr,
                                           const size_t parseCount,
                                           std::vector<std::string> *outInstructionAsm,
                                           std::vector<RegisterInfo> *outRegInfo = NULL);

        unsigned
        convertInstructionSequenceToString(const byteSequence& instructionSequence,
                                           AssemblySyntax asmSyntax,
                                           addressType addr,
                                           const size_t parseCount,
                                           std::vector<std::string> *outInstructionAsm,
                                           std::vector<RegisterInfo> *outRegInfo = NULL);

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

        /**
         * Takes the input assembly string of some instruction(s) and prints
         * what detailed information Capstone knows about these instructions.
         * Note: The instruction is first converted to bytes with Keystone and then converted back with Capstone.
         * @param instructionSequenceAsm The instruction(s), given in assembly, as a string. Multiple instructions are separated by ";".
         * @param inputAsmSyntax The assembly syntax of the input instructions.
         * @param addr The virtual memory address of the first instruction.
         *             This might influence the output for some instructions.
         */
        void printCapstoneInformationForInstructions(std::string instructionSequenceAsm,
                                                     AssemblySyntax inputAsmSyntax,
                                                     addressType addr = 0ULL);

        ~InstructionConverter();


        // Turn X86_REG_RAX to "X86_REG_RAX";
        static const char * convertCapstoneRegIdToString(x86_reg regId);
        // Turn X86_REG_RAX to "RAX";
        static const char * convertCapstoneRegIdToShortString(x86_reg regId);

        // Turn "rax" to X86_REG_RAX;
        static x86_reg convertRegShortStringToCapstoneRegId(std::string regString);
    };

}


#endif // INSTRUCTION_CONVERTER_H
