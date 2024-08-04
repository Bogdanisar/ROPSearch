#ifndef INS_SEQ_TRIE_H
#define INS_SEQ_TRIE_H

#include <map>
#include <string>
#include <vector>


namespace ROOP {

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
            std::vector<unsigned long long> matchingVirtualAddresses;
            std::map<std::string, Node *> children;
        };

        private:
        void recursiveFree(Node *currentNode);

        public:
        // The root node, corresponding to the empty instruction sequence.
        Node *root;

        InsSeqTrie();

        Node* addInstruction(const std::string& instruction, unsigned long long vaAddress);
        Node* addInstruction(const std::string& instruction, unsigned long long vaAddress, Node *node);

        std::vector<unsigned long long> hasInstructionSequence(const std::vector<std::string>& instructionSequence) const;

        ~InsSeqTrie();
    };

}


#endif // INS_SEQ_TRIE_H
