#include "InsSeqTrie.hpp"

#include <algorithm>
#include <cassert>


ROP::InsSeqTrie::InsSeqTrie() {
    this->root = new Node;
}

ROP::InsSeqTrie::Node* ROP::InsSeqTrie::addInstruction(const std::string& instruction, unsigned long long vAddress, Node *node) {
    if (node->children.count(instruction) == 0) {
        node->children[instruction] = new Node;
    }

    Node *childNode = node->children[instruction];
    childNode->matchingVirtualAddresses.push_back(vAddress);

    return childNode;
}

ROP::InsSeqTrie::Node* ROP::InsSeqTrie::addInstruction(const std::string& instruction, unsigned long long vAddress) {
    return this->addInstruction(instruction, vAddress, this->root);
}

std::vector<unsigned long long> ROP::InsSeqTrie::hasInstructionSequence(const std::vector<std::string>& instructionSequence) const {
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

void ROP::InsSeqTrie::getTrieContent(Node *currentNode,
                                      const std::vector<std::string>& currInstrSeq,
                                      std::vector< std::pair<unsigned long long, std::vector<std::string>> >& content) const
{
    assert(currentNode == this->root || currentNode->matchingVirtualAddresses.size() != 0);
    if (currentNode->matchingVirtualAddresses.size() != 0) {
        for (unsigned long long addr : currentNode->matchingVirtualAddresses) {
            content.push_back({addr, currInstrSeq});
        }
    }

    for (const auto& c : currentNode->children) {
        const std::string& nextInstr = c.first;
        Node *nextNode = c.second;

        auto nextInstrSeq = currInstrSeq;
        nextInstrSeq.push_back(nextInstr);

        this->getTrieContent(nextNode, nextInstrSeq, content);
    }
}

std::vector< std::pair<unsigned long long, std::vector<std::string>> >
ROP::InsSeqTrie::getTrieContent() const
{
    std::vector< std::pair<unsigned long long, std::vector<std::string>> > content;
    this->getTrieContent(this->root, {}, content);

    // The Instruction Sequence vectors need to be reversed.
    for (auto &p : content) {
        std::vector<std::string>& instrSeq = p.second;
        std::reverse(instrSeq.begin(), instrSeq.end());
    }

    return content;
}

void ROP::InsSeqTrie::recursiveFree(Node *currentNode) {
    for (const auto& keyValuePair : currentNode->children) {
        Node *child = keyValuePair.second;
        this->recursiveFree(child);
    }

    delete currentNode;
}

ROP::InsSeqTrie::~InsSeqTrie() {
    this->recursiveFree(this->root);
}
