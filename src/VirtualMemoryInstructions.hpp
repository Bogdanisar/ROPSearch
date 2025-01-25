#ifndef VIRTUAL_MEMORY_INSTRUCTIONS_H
#define VIRTUAL_MEMORY_INSTRUCTIONS_H

#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "InsSeqTrie.hpp"
#include "InstructionConverter.hpp"
#include "VirtualMemoryExecutableBytes.hpp"


namespace ROP {

    class VirtualMemoryInstructions {
        VirtualMemoryExecutableBytes vmExecBytes;
        InstructionConverter ic;
        InsSeqTrie instructionTrie;
        std::vector<RegisterInfo> auxRegInfoVector;

        /*
        This data structure is used for optimizing (through memoization) the construction of the inner trie.
        - `disassembledSegment[first]` == `{last, instruction}`,
          if `[first, last]` is a valid bytes segment that disassembles into `instruction`.
          This segment is unique for `first` (if it exists).
        - `disassembledSegment[first]` == `{-1, ""}`,
          if there is no valid `[first, last]` bytes segment (for the purpose of disassembly).
        */
        std::unordered_map<int, std::pair<int, std::string>> disassembledSegment;

        /*
        This data structure is used for optimizing (through memoization) the construction of the inner trie.
        `regInfoForSegment[first]` = The register information associated with the instruction at
        the `[first, last]` bytes segment described by `disassembledSegment[first]`,
        if the segment is valid and the register information was queried.
        */
        std::unordered_map<int, RegisterInfo> regInfoForSegment;

        // Check if there is an index "last" such that [first, last] can be disassembled into a valid instruction.
        // Note: Since x86 is a prefix-free architecture, this "last" index is unique (if it exists).
        void disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first);

        void buildInstructionTrie(
            const VirtualMemoryExecutableSegment& segm,
            const int currRightSegmentIdx,
            InsSeqTrie::Node *currNode,
            const int currInstrSeqLength
        );

        void buildInstructionTrie();


        public:
        // Default value: 10.
        static int MaxInstructionsInInstructionSequence;
        // Default value: AssemblySyntax::Intel.
        static AssemblySyntax innerAssemblySyntax;
        // Default value: false.
        static bool computeRegisterInfo;

        /**
         * Get executable bytes by reading the "/proc/PID/maps" file
         * and then loading executable segments from each ELF file according to the mapping.
         */
        VirtualMemoryInstructions(int processPid);

        /**
         * Load all executable segments from each given executable path.
         * @param execPaths Paths to executable files.
         * @param baseAddresses Values that will be used, in order, as a base address
         *                      for each executable segment that we find in the given executable files.
         *                      If this array is empty or has fewer addresses than the total number of segments,
         *                      the Elf64_Phdr.p_vaddr value found in the ELF file will be used instead.
         */
        VirtualMemoryInstructions(const std::vector<std::string> execPaths,
                                  const std::vector<unsigned long long> baseAddresses);

        // Return a vector of addresses where the instruction sequence is found in virtual memory.
        std::vector<unsigned long long>
        matchInstructionSequenceInVirtualMemory(std::string instructionSequenceAsm, AssemblySyntax asmSyntax);

        // Return a vector of pairs of (virtual memory address, instruction sequence).
        std::vector< std::pair<unsigned long long, std::vector<std::string>> >
        getInstructionSequences(std::vector<std::vector<RegisterInfo>> *outRegInfo = NULL) const;
    };

}


#endif // VIRTUAL_MEMORY_INSTRUCTIONS_H
