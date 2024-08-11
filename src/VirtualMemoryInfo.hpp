#ifndef VIRTUAL_MEMORY_INFO_H
#define VIRTUAL_MEMORY_INFO_H

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
#include "VirtualMemoryMapping.hpp"


namespace ROOP {

    struct VirtualMemoryExecutableSegment {
        // The end address might be larger than start + bytes.size(),
        // because of needing to be a multiple of the page size.
        unsigned long long startVirtualAddress;
        unsigned long long endVirtualAddress;
        byteSequence executableBytes;
    };

    class VirtualMemoryInfo {
        VirtualMemoryMapping vaSegmMapping;
        std::vector<VirtualMemoryExecutableSegment> executableSegments;
        InstructionConverter ic;
        InsSeqTrie instructionTrie;

        void buildExecutableSegments();


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
        VirtualMemoryInfo(int processPid);

        const VirtualMemoryMapping& getVASegmMapping() const;
        const std::vector<VirtualMemoryExecutableSegment>& getExecutableSegments() const;

        bool isValidVAAddressInExecutableSegment(unsigned long long vaAddress) const;
        byte getByteAtVAAddress(unsigned long long vaAddress) const;

        // Return a vector of addresses where the instruction sequence is found in virtual memory.
        std::vector<unsigned long long>
        matchInstructionSequenceInVirtualMemory(byteSequence instructionSequence);

        // Return a vector of addresses where the instruction sequence is found in virtual memory.
        std::vector<unsigned long long>
        matchInstructionSequenceInVirtualMemory(std::string instructionSequenceAsm, AssemblySyntax asmSyntax);
    };

}


#endif // VIRTUAL_MEMORY_INFO_H
