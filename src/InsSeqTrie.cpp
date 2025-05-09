#include "InsSeqTrie.hpp"

#include <algorithm>
#include <cassert>


ROP::InsSeqTrie::InsSeqTrie() {
    this->root = new Node;
}

ROP::InsSeqTrie::Node* ROP::InsSeqTrie::addInstruction(
    const std::string& instruction,
    addressType vAddress,
    Node *node,
    const RegisterInfo *regInfo
) {
    if (node->children.count(instruction) == 0) {
        node->children[instruction] = new Node;
    }

    Node *childNode = node->children[instruction];
    childNode->matchingVirtualAddresses.push_back(vAddress);

    if (regInfo) {
        childNode->regInfo = *regInfo;
    }

    return childNode;
}

ROP::InsSeqTrie::Node* ROP::InsSeqTrie::addInstruction(
    const std::string& instruction,
    addressType vAddress,
    const RegisterInfo *regInfo
) {
    return this->addInstruction(instruction, vAddress, this->root, regInfo);
}

std::vector<ROP::addressType> ROP::InsSeqTrie::hasInstructionSequence(const std::vector<std::string>& instructionSequence) const {
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
                                     const std::vector<RegisterInfo>& currRegInfoSeq,
                                     std::vector< std::pair<addressType, std::vector<std::string>> >& content,
                                     std::vector<std::vector<RegisterInfo>> *outRegInfo) const
{
    assert(currentNode == this->root || currentNode->matchingVirtualAddresses.size() != 0);
    if (currentNode->matchingVirtualAddresses.size() != 0) {
        for (addressType addr : currentNode->matchingVirtualAddresses) {
            content.push_back({addr, currInstrSeq});
            if (outRegInfo) {
                (*outRegInfo).push_back(currRegInfoSeq);
            }
        }
    }

    for (const auto& c : currentNode->children) {
        const std::string& nextInstr = c.first;
        Node *nextNode = c.second;

        auto nextInstrSeq = currInstrSeq;
        nextInstrSeq.push_back(nextInstr);

        if (outRegInfo) {
            auto nextRegInfoSeq = currRegInfoSeq;
            nextRegInfoSeq.push_back(nextNode->regInfo);

            this->getTrieContent(nextNode, nextInstrSeq, nextRegInfoSeq, content, outRegInfo);
        }
        else {
            this->getTrieContent(nextNode, nextInstrSeq, {}, content, NULL);
        }
    }
}

std::vector< std::pair<ROP::addressType, std::vector<std::string>> >
ROP::InsSeqTrie::getTrieContent(std::vector<std::vector<RegisterInfo>> *outRegInfo) const
{
    std::vector< std::pair<addressType, std::vector<std::string>> > content;
    this->getTrieContent(this->root, {}, {}, content, outRegInfo);

    // The Instruction Sequence vectors need to be reversed.
    for (auto &p : content) {
        std::vector<std::string>& instrSeq = p.second;
        std::reverse(instrSeq.begin(), instrSeq.end());
    }

    if (outRegInfo) {
        for (auto &regInfoSeq : *outRegInfo) {
            std::reverse(regInfoSeq.begin(), regInfoSeq.end());
        }
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
