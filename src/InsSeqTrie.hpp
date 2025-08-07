#ifndef INS_SEQ_TRIE_H
#define INS_SEQ_TRIE_H

#include <bitset>
#include <map>
#include <string>
#include <vector>

#include "InstructionConverter.hpp"


namespace ROP {

    // A class that efficiently stores, through a Trie structure, all the instruction sequences
    // decoded from the executable bytes present in the virtual address space of a process.
    class InsSeqTrie {
        public:
        // A given instruction sequence is codified in the Trie
        // by a path from the root node to a descendant node
        // (from the last instruction in the sequence to the first instruction).
        // Therefore, each node in the structure corresponds to a valid instruction sequence.
        struct Node {
            // A list of virtual addresses where the ins sequence denoted by this node can be found.
            std::vector<addressType> matchingVirtualAddresses;
            RegisterInfo regInfo;

            std::map<std::string, Node *> children;
        };

        private:
        void recursiveFree(Node *currentNode);

        void getTrieContent(Node *currentNode,
                            const std::vector<std::string>& currInstrSeq,
                            const std::vector<RegisterInfo>& currRegInfoSeq,
                            std::vector< std::pair<addressType, std::vector<std::string>> >& content,
                            std::vector<std::vector<RegisterInfo>> *outRegInfo) const;

        public:
        // The root node, corresponding to the empty instruction sequence.
        Node *root;

        // Config values.
        BitSizeClass archBitSize;
        std::bitset<256> badAddressBytes;
        unsigned numBadAddressBytes = 0; // optimization since bitset::count() is not constant.
        bool ignoreDuplicateInstructionSequenceResults = true;
        bool ignoreOutputSequencesThatStartWithDirectRelativeJumps = true;

        InsSeqTrie();

        // The copy constructor and copy assignment operator
        // would require extra work and we don't need them.
        InsSeqTrie(InsSeqTrie& other) = delete;
        InsSeqTrie& operator=(InsSeqTrie& other) = delete;

        // Move constructor and move assignment operator are implemented.
        InsSeqTrie(InsSeqTrie&& other);
        InsSeqTrie& operator=(InsSeqTrie&& other);


        Node* addInstruction(const std::string& instruction,
                             addressType vAddress,
                             const RegisterInfo *regInfo = NULL);

        Node* addInstruction(Node *referenceNode,
                             const std::string& instruction,
                             addressType vAddress,
                             const RegisterInfo *regInfo = NULL);

        std::vector<addressType> hasInstructionSequence(const std::vector<std::string>& instructionSequence) const;

        // Return a vector of pairs of (virtual memory address, instruction sequence).
        std::vector< std::pair<addressType, std::vector<std::string>> >
        getTrieContent(std::vector<std::vector<RegisterInfo>> *outRegInfo = NULL) const;

        ~InsSeqTrie();
    };

}


#endif // INS_SEQ_TRIE_H
