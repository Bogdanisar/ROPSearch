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
#include "VirtualMemoryBytes.hpp"


namespace ROP {

    class VirtualMemoryInstructions {
        VirtualMemoryBytes vmBytes;
        InstructionConverter ic;
        BitSizeClass archBitSize; // 32bit or 64bit;
        std::vector<RegisterInfo> auxRegInfoVector;

        bool didBuildInstructionTrie = false;
        InsSeqTrie instructionTrie;

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

        /**
         * `jmpIndexesForAddress[ThisAddress]` = List of indexes `first` such that
         * the `[first, last]` bytes segment disassembles to a "jmp 0xThisAddress" instruction,
         * for the corresponding value `last` for the index `first`.
         * This is used for finding instruction sequences that have a direct relative jump in the middle.
         * Example: "pop rax; jmp 0x01020304 --> pop rbx; ret".
         */
        std::unordered_map<ROP::addressType, std::set<int>> jmpIndexesForAddress;


        // Look for direct relative jmp instructions and build `jmpIndexesForAddress`.
        void buildRelativeJmpMap(const VirtualMemorySegmentBytes& segm);

        // Check if there is an index "last" such that [first, last] can be disassembled into a valid instruction.
        // Note: Since x86 is a prefix-free architecture, this "last" index is unique (if it exists).
        void disassembleSegmentBytes(const VirtualMemorySegmentBytes& segm, const int first);

        void extendInstructionSequenceThroughDirectlyPrecedingInstructions(
            const VirtualMemorySegmentBytes& segm,
            InsSeqTrie::Node *prevNode,
            const int prevFirstIndex,
            const addressType prevVMAddress,
            const int prevInstrSeqLength
        );
        void extendInstructionSequenceThroughRelativeJmpInstructions(
            const VirtualMemorySegmentBytes& segm,
            InsSeqTrie::Node *prevNode,
            const int prevFirstIndex,
            const addressType prevVMAddress,
            const int prevInstrSeqLength
        );
        void extendInstructionSequenceAndAddToTrie(
            const VirtualMemorySegmentBytes& segm,
            InsSeqTrie::Node *prevNode,
            const int prevFirstIndex,
            const addressType prevVMAddress,
            const int prevInstrSeqLength
        );

        public:

        /**
         * Default constructor so that the object can be initialized empty.
         * Don't use an object initialized in this way.
        */
        VirtualMemoryInstructions() = default;

        /**
         * Get executable bytes by reading the "/proc/PID/maps" file
         * and then loading executable segments from each ELF file according to the mapping.
         */
        VirtualMemoryInstructions(int processPid);

        /**
         * Load all executable segments from each given executable path.
         * @param execPaths Paths to executable files.
         * @param baseAddresses Values that will be used, in order, as a base address for each executable file.
         *                      If this array is empty or has fewer addresses than the total number of files,
         *                      then the value 0 will be used as a default.
         */
        VirtualMemoryInstructions(const std::vector<std::string> execPaths,
                                  const std::vector<addressType> baseAddresses);


        //////////////////////// Config values ////////////////////////

        int minInstructionsInInstructionSequence = 1;
        int maxInstructionsInInstructionSequence = 10;

        // Ignore results where the virtual address contains any of these bytes.
        std::bitset<256> badAddressBytes;

        // Keep just the first virtual address that we find for a given sequence.
        bool ignoreDuplicateInstructionSequenceResults = true;

        // Include instruction sequences like "xor eax, eax; jmp 0xee877518 --> pop edi; pop esi; ret".
        bool searchForSequencesWithDirectRelativeJumpsInTheMiddle = true;

        // Ignore instruction sequences like "jmp 0xee877518 --> pop edi; pop esi; ret"
        // (since the starting `jmp` instruction doesn't add value by itself).
        bool ignoreOutputSequencesThatStartWithDirectRelativeJumps = true;

        // The assembly syntax that will be output by Capstone when disassembling.
        AssemblySyntax innerAssemblySyntax = AssemblySyntax::Intel;

        // Tell Capstone to compute the extra detail information when building the ins seq trie.
        // Default value: false (details aren't always needed).
        bool computeRegisterInfo = false;

        //////////////////////// Config values ////////////////////////


        // If you want to change the default configuration, change it before calling this method.
        // You must not change the configuration after calling this method.
        // You must call this method before getting the instruction sequences.
        void buildInstructionTrie();


        // Copy constructor and copy assignment operator don't make sense
        // for this class because of the InstructionConverter object.
        VirtualMemoryInstructions(VirtualMemoryInstructions& other) = delete;
        VirtualMemoryInstructions& operator=(VirtualMemoryInstructions& other) = delete;

        // Move constructor and move assignment operator are implemented.
        VirtualMemoryInstructions(VirtualMemoryInstructions&& other) = default;
        VirtualMemoryInstructions& operator=(VirtualMemoryInstructions&& other) = default;


        // Getter.
        const VirtualMemoryBytes& getVirtualMemoryBytes() const;

        // Return a vector of addresses where the instruction sequence is found in virtual memory.
        std::vector<addressType>
        matchInstructionSequenceInVirtualMemory(std::string instructionSequenceAsm, AssemblySyntax asmSyntax);

        // Return a vector of pairs of (virtual memory address, instruction sequence).
        std::vector< std::pair<addressType, std::vector<std::string>> >
        getInstructionSequences(std::vector<std::vector<RegisterInfo>> *outRegInfo = NULL) const;
    };

}


#endif // VIRTUAL_MEMORY_INSTRUCTIONS_H
