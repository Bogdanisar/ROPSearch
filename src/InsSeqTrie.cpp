#include "InsSeqTrie.hpp"


ROOP::InsSeqTrie::InsSeqTrie() {
    this->root = new Node;
}

ROOP::InsSeqTrie::Node* ROOP::InsSeqTrie::addInstruction(const std::string& instruction, unsigned long long vaAddress, Node *node) {
    if (node->children.count(instruction) == 0) {
        node->children[instruction] = new Node;
    }

    Node *childNode = node->children[instruction];
    childNode->matchingVirtualAddresses.push_back(vaAddress);

    return childNode;
}

ROOP::InsSeqTrie::Node* ROOP::InsSeqTrie::addInstruction(const std::string& instruction, unsigned long long vaAddress) {
    return this->addInstruction(instruction, vaAddress, this->root);
}

std::vector<unsigned long long> ROOP::InsSeqTrie::hasInstructionSequence(const std::vector<std::string>& instructionSequence) const {
    Node *currentNode = this->root;
    for (auto it = instructionSequence.rbegin(); it != instructionSequence.rend(); ++it) {
        const std::string& instruction = *it;
        if (currentNode->children.count(instruction) == 0) {
            return {};
        }

        currentNode = currentNode->children[instruction];
    }

    return currentNode->matchingVirtualAddresses;
}

void ROOP::InsSeqTrie::recursiveFree(Node *currentNode) {
    for (const auto& keyValuePair : currentNode->children) {
        Node *child = keyValuePair.second;
        this->recursiveFree(child);
    }

    delete currentNode;
}

ROOP::InsSeqTrie::~InsSeqTrie() {
    this->recursiveFree(this->root);
}
