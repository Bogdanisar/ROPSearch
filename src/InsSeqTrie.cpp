#include "InsSeqTrie.hpp"

#include <algorithm>
#include <cassert>


// Default constructor.
ROP::InsSeqTrie::InsSeqTrie() {
    this->root = new Node;
}

// Move constructor.
ROP::InsSeqTrie::InsSeqTrie(InsSeqTrie&& other)
: InsSeqTrie() {
    // Reuse the move assignment operator code;
    *this = std::move(other);
}

// Move assignment operator.
ROP::InsSeqTrie& ROP::InsSeqTrie::operator=(InsSeqTrie&& other) {
    std::swap(this->root, other.root);
    std::swap(this->ignoreOutputSequencesThatStartWithDirectRelativeJumps,
              other.ignoreOutputSequencesThatStartWithDirectRelativeJumps);
    return *this;
}


ROP::InsSeqTrie::Node* ROP::InsSeqTrie::addInstruction(
    Node *referenceNode,
    const std::string& instruction,
    addressType vAddress,
    const RegisterInfo *regInfo
) {
    if (referenceNode->children.count(instruction) == 0) {
        referenceNode->children[instruction] = new Node;
    }
    Node *childNode = referenceNode->children[instruction];

    if (this->numBadAddressBytes != 0
        && RegisterSizedConstantHasBadBytes(this->archBitSize, this->badAddressBytes, vAddress)) {
        // Don't add this address since it has bad bytes.
        return childNode;
    }

    if (this->ignoreDuplicateInstructionSequenceResults && childNode->matchingVirtualAddresses.size() != 0) {
        // Don't add this address since it's a duplicate.
        return childNode;
    }

    // Set the new information on the child node.
    childNode->matchingVirtualAddresses.push_back(vAddress);
    if (regInfo) { childNode->regInfo = *regInfo; }

    return childNode;
}

ROP::InsSeqTrie::Node* ROP::InsSeqTrie::addInstruction(
    const std::string& instruction,
    addressType vAddress,
    const RegisterInfo *regInfo
) {
    return this->addInstruction(this->root, instruction, vAddress, regInfo);
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
    assert(currentNode->matchingVirtualAddresses.size() != 0
           || currentNode == this->root
           || this->numBadAddressBytes != 0);

    if (currentNode->matchingVirtualAddresses.size() != 0) {
        for (addressType addr : currentNode->matchingVirtualAddresses) {

            if (this->ignoreOutputSequencesThatStartWithDirectRelativeJumps) {
                const std::string& startInstruction = currInstrSeq.back();
                bool startInstructionIsRelativeJump = (startInstruction.find("-->") != std::string::npos);
                if (startInstructionIsRelativeJump) {
                    // Don't add this sequence to the output list.
                    continue;
                }
            }

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
