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

        /*
        This data structure is used for optimizing (through memoization) the construction of the inner trie.
        - disassembledSegment[first] == {last, instruction},
          if [first, last] is a valid bytes segment that disassembles into "instruction".
        - disassembledSegment[first] == {-1, ""},
          if there is no valid [first, last] bytes segment (for the purpose of disassembly).
        */
        std::unordered_map<int, std::pair<int, std::string>> disassembledSegment;

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
        static int MaxInstructionsInInstructionSequence;
        static AssemblySyntax innerAssemblySyntax;

        VirtualMemoryInstructions(int processPid);
        VirtualMemoryInstructions(const std::vector<std::string> execPaths,
                                  const std::vector<unsigned long long> baseAddresses);

        // Return a vector of addresses where the instruction sequence is found in virtual memory.
        std::vector<unsigned long long>
        matchInstructionSequenceInVirtualMemory(std::string instructionSequenceAsm, AssemblySyntax asmSyntax);

        // Return a vector of pairs of (virtual memory address, instruction sequence).
        std::vector< std::pair<unsigned long long, std::vector<std::string>> > getInstructionSequences() const;
    };

}


#endif // VIRTUAL_MEMORY_INSTRUCTIONS_H
