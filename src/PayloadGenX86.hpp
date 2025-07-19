#ifndef PAYLOAD_GEN_X86_H
#define PAYLOAD_GEN_X86_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include <capstone/capstone.h>
#include "common/types.hpp"
#include "VirtualMemoryInstructions.hpp"


// Forward declarations for friend functions.
void testPayloadGeneration(std::string targetExecutable);


namespace ROP {

    // An object of this class will be used for generating an attack payload
    // for the given target process or executables.
    // The class is specialized for the x86 architecture.
    class PayloadGenX86 {
        VirtualMemoryInstructions vmInstructionsObject;
        std::vector< std::pair<addressType, std::vector<std::string>> > instrSeqs;
        std::vector< std::vector<RegisterInfo> > regInfoSeqs;
        /**
         * Indexes into `instrSeqs` and `regInfoSeqs`.
         * We use this in order to be able to do sorting and filtering.
         */
        std::vector<unsigned> sequenceIndexList;

        BitSizeClass processArchSize;
        unsigned numBytesOfAddress;

        /**
         * Example on 64bit:
         * `regToMainReg[X86_REG_RAX]` = X86_REG_RAX.
         * Example on 32bit:
         * `regToMainReg[X86_REG_RAX]` = X86_REG_EAX.
         * Note: The map is always keyed by the 64bit reg identifiers, not the 32bit ones.
         */
        std::map<x86_reg, x86_reg> regToMainReg;

        /**
         * Example on 64bit:
         * `regToPartialRegs[X86_REG_RAX]` = {_RAX, _EAX, _AX, _AH, _AL}.
         * Example on 32bit:
         * `regToPartialRegs[X86_REG_RAX]` = {_EAX, _AX, _AH, _AL}.
         * Note: The map is always keyed by the 64bit reg identifiers, not the 32bit ones.
         */
        std::map<x86_reg, std::set<x86_reg>> regToPartialRegs;

        /**
         * Example on 64bit:
         * `regToEndingPartialRegs[X86_REG_RAX]` = {_RAX, _EAX, _AX, _AL}, but not _AH.
         * Example on 32bit:
         * `regToEndingPartialRegs[X86_REG_RAX]` = {_EAX, _AX, _AL}, but not _AH.
         * Note: The map is always keyed by the 64bit reg identifiers, not the 32bit ones.
         */
        std::map<x86_reg, std::set<x86_reg>> regToEndingPartialRegs;


        byteSequence payloadBytes = {};
        std::vector<std::string> pythonScript = {};


        void preconfigureVMInstructionsObject();
        void computeRelevantSequenceIndexes();
        void preloadTheRegisterMaps();

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
         * Search for an instruction sequence that starts with the given instruction.
         * Also, it checks that the rest of the instructions in the sequence don't write to
         * the forbidden registers given in the argument, or to any memory region
         * (i.e. it checks that the remaining instructions are effective NOPs).
         * @return The index of the found sequence, in the sequence vector. Otherwise, the size of the vector.
         */
        unsigned searchForSequenceStartingWithInstruction(const std::string& targetInstruction,
                                                          const std::set<x86_reg>& forbiddenRegisters);

        bool searchGadgetForAssignValueToRegister(x86_reg reg,
                                                  const uint64_t value,
                                                  std::set<x86_reg> forbiddenRegisters,
                                                  bool shouldAppend = false);

        public:
        void writePayloadToFile(const std::string& filename);
        void writeScriptToFile(const std::string& filename);

        public:
        // Mark these functions as friends so that they can access private members.
        friend void ::testPayloadGeneration(std::string targetExecutable);
    };

}


#endif // PAYLOAD_GEN_X86_H
