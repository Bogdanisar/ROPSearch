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


        // These data structures are used for optimizing (through memoization) the construction of the inner trie.
        struct IntPairHasher {
            inline std::size_t operator()(const std::pair<int,int>& v) const {
                return 31*v.first + v.second;
            }
        };
        std::unordered_set<std::pair<int,int>, IntPairHasher> disassembledSegments;
        std::unordered_map<int, std::unordered_map<int, std::string>> segmentToInstruction;

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
