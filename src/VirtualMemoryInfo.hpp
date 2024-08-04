#ifndef VIRTUAL_MEMORY_INFO_H
#define VIRTUAL_MEMORY_INFO_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "InsSeqTrie.hpp"
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
        InsSeqTrie instructionTrie;

        void buildExecutableSegments();


        // Used as an optimization (through memoization) when building the inner trie;
        std::set<std::pair<int,int>> disassembledSegments;
        std::map<std::pair<int,int>, std::string> segmentToInstruction;

        void disassembleSegmentBytes(const VirtualMemoryExecutableSegment& segm, const int first, const int last);

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
