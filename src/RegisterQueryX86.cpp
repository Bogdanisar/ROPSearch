#include "RegisterQueryX86.hpp"

#include <string.h>

#include "InstructionConverter.hpp"


static const char * const PRECEDENCE_TO_OPERATOR_TOKEN[] = {"||", "&&", "!=", "==", "!"};
static ROP::RegisterQueryX86::QueryNodeType PRECEDENCE_TO_OPERATOR_TYPE[] = {
    ROP::RegisterQueryX86::QueryNodeType::OR_OPERATOR,
    ROP::RegisterQueryX86::QueryNodeType::AND_OPERATOR,
    ROP::RegisterQueryX86::QueryNodeType::NOT_EQUALS_OPERATOR,
    ROP::RegisterQueryX86::QueryNodeType::EQUALS_OPERATOR,
    ROP::RegisterQueryX86::QueryNodeType::NOT_OPERATOR,
};

static const int MAX_PRECEDENCE = sizeof(PRECEDENCE_TO_OPERATOR_TOKEN) / sizeof(PRECEDENCE_TO_OPERATOR_TOKEN[0]);


static std::string GetLowercaseString(std::string str) {
    for (char& c : str) {
        c = tolower(c);
    }
    return str;
}

static std::string GetStringNoWhitespace(const std::string& str) {
    std::string ans;
    ans.reserve(str.size());

    for (const char& c : str) {
        if (!isspace(c)) {
            ans.push_back(c);
        }
    }

    return ans;
}


void ROP::RegisterQueryX86::precomputeTermStrings() {
    // Precompute this->registerTermStrings.
    for (unsigned regIndex = X86_REG_INVALID + 1; regIndex < (unsigned)X86_REG_ENDING; ++regIndex) {
        x86_reg regID = (x86_reg)regIndex;

        // Turn a register ID (e.g. X86_REG_RAX) into a string like "RAX".
        const char *regCString = ROP::InstructionConverter::convertCapstoneRegIdToShortString(regID);

        for (const char * const kind : {"read", "anyread", "allread", "write", "anywrite", "allwrite"}) {
            // Get a string like "read(RAX)" or "write(RAX)".
            std::string currTermString = std::string(kind) + "(" + std::string(regCString) + ")";

            // Turn to lowercase.
            for(char& c : currTermString) {
                c = tolower(c);
            }

            if (std::string(kind) == "read" || std::string(kind) == "anyread") {
                this->registerTermStrings.push_back({currTermString, QueryNodeType::ANY_READ_REGISTER, regID});
            }
            else if (std::string(kind) == "allread") {
                this->registerTermStrings.push_back({currTermString, QueryNodeType::ALL_READ_REGISTER, regID});
            }
            else if (std::string(kind) == "write" || std::string(kind) == "anywrite") {
                this->registerTermStrings.push_back({currTermString, QueryNodeType::ANY_WRITE_REGISTER, regID});
            }
            else {
                assert(std::string(kind) == "allwrite");
                this->registerTermStrings.push_back({currTermString, QueryNodeType::ALL_WRITE_REGISTER, regID});
            }
        }
    }

    // Precompute this->memoryOperandTermStrings.
    for (const char * const literal : {"memop", "memory_operand"}) {
        for (const char * const kind : {"read", "anyread", "allread", "write", "anywrite", "allwrite"}) {
            // Get a string like "read(memop)" or "write(memop)".
            std::string currTermString = std::string(kind) + "(" + std::string(literal) + ")";

            // Turn to lowercase.
            for(char& c : currTermString) {
                c = tolower(c);
            }

            if (std::string(kind) == "read" || std::string(kind) == "anyread") {
                StoredTermString term = {currTermString, QueryNodeType::ANY_READ_MEMORY_OPERAND};
                this->memoryOperandTermStrings.push_back(term);
            }
            else if (std::string(kind) == "allread") {
                StoredTermString term = {currTermString, QueryNodeType::ALL_READ_MEMORY_OPERAND};
                this->memoryOperandTermStrings.push_back(term);
            }
            else if (std::string(kind) == "write" || std::string(kind) == "anywrite") {
                StoredTermString term = {currTermString, QueryNodeType::ANY_WRITE_MEMORY_OPERAND};
                this->memoryOperandTermStrings.push_back(term);
            }
            else {
                assert(std::string(kind) == "allwrite");
                StoredTermString term = {currTermString, QueryNodeType::ALL_WRITE_MEMORY_OPERAND};
                this->memoryOperandTermStrings.push_back(term);
            }
        }
    }

    // Precompute this->immediateValueTermStrings.
    for (const char * const literal : {"imm", "immediate_value"}) {
        for (const char * const kind : {"have", "anyhave", "allhave"}) {
            // Get a string like "anyhave(imm)".
            std::string currTermString = std::string(kind) + "(" + std::string(literal) + ")";

            // Turn to lowercase.
            for(char& c : currTermString) {
                c = tolower(c);
            }

            if (std::string(kind) == "have" || std::string(kind) == "anyhave") {
                StoredTermString term = {currTermString, QueryNodeType::ANY_HAVE_IMMEDIATE_VALUE};
                this->immediateValueTermStrings.push_back(term);
            }
            else {
                assert(std::string(kind) == "allhave");
                StoredTermString term = {currTermString, QueryNodeType::ALL_HAVE_IMMEDIATE_VALUE};
                this->immediateValueTermStrings.push_back(term);
            }
        }
    }
}

ROP::RegisterQueryX86::QueryNode*
ROP::RegisterQueryX86::parseQueryLeaf() {
    // Check if the current part of the query is a basic expression term (e.g. "true" or "read(RSI)")
    // and return a corresponding node structure for the parsed subquery.

    if (strncmp(this->queryCString + this->queryIdx, "true", 4) == 0) {
        // Go over the parsed string.
        this->queryIdx += 4;

        QueryNode *node = new QueryNode();
        node->nodeType = QueryNodeType::VALUE_TRUE;
        return node;
    }

    if (strncmp(this->queryCString + this->queryIdx, "false", 5) == 0) {
        // Go over the parsed string.
        this->queryIdx += 5;

        QueryNode *node = new QueryNode();
        node->nodeType = QueryNodeType::VALUE_FALSE;
        return node;
    }

    // Look for basic terms that relate to registers, like "read(reg)" or "write(reg)".
    for (const auto& regTermInfo : this->registerTermStrings) {
        const x86_reg& regID = regTermInfo.regID;
        const std::string& termString = regTermInfo.termString;
        const QueryNodeType& queryNodeType = regTermInfo.nodeType;

        if (strncmp(this->queryCString + this->queryIdx, termString.c_str(), termString.size()) == 0) {
            // Go over the parsed string.
            this->queryIdx += (int)termString.size();

            QueryNode *node = new QueryNode();
            node->nodeType = queryNodeType;
            node->registerID = regID;
            return node;
        }
    }

    // Look for basic terms that relate to memory_operands, like "read(reg)" or "write(reg)".
    for (const auto& memTermInfo : this->memoryOperandTermStrings) {
        const std::string& termString = memTermInfo.termString;
        const QueryNodeType& queryNodeType = memTermInfo.nodeType;

        if (strncmp(this->queryCString + this->queryIdx, termString.c_str(), termString.size()) == 0) {
            // Go over the parsed string.
            this->queryIdx += (int)termString.size();

            QueryNode *node = new QueryNode();
            node->nodeType = queryNodeType;
            return node;
        }
    }

    // Look for basic terms that relate to immediate values, like "anyhave(imm)" or "allhave(imm)".
    for (const auto& immTermInfo : this->immediateValueTermStrings) {
        const std::string& termString = immTermInfo.termString;
        const QueryNodeType& queryNodeType = immTermInfo.nodeType;

        if (strncmp(this->queryCString + this->queryIdx, termString.c_str(), termString.size()) == 0) {
            // Go over the parsed string.
            this->queryIdx += (int)termString.size();

            QueryNode *node = new QueryNode();
            node->nodeType = queryNodeType;
            return node;
        }
    }

    LogError("Expected \"true\", \"false\", "
             "\"read(reg)\", \"anyread(reg)\", \"allread(reg)\", "
             "\"write(reg)\", \"anywrite(reg)\", \"allwrite(reg)\" "
             "\"read(memory_operand)\", \"anyread(memory_operand)\", \"allread(memory_operand)\", "
             "\"write(memory_operand)\", \"anywrite(memory_operand)\", \"allwrite(memory_operand)\", "
             "\"have(immediate_value)\", \"anyhave(immediate_value)\", \"allhave(immediate_value)\" "
             "when parsing register query at index %u.", this->queryIdx);
    return NULL;
}

bool
ROP::RegisterQueryX86::nextQueryCharacterIsValid(unsigned currentPrecedence) {
    // This function is meant to be called after a term is parsed and the index is at the next character.
    // The next character is only valid if it corresponds to the operator for the current precedence
    // or the operators for lower precedences or the ')' character or the end of the string ('\0').
    // Otherwise, the query string is malformed.

    if (this->queryIdx == this->queryString.size() || this->queryCString[this->queryIdx] == '\0') {
        // All the string got parsed correctly, so we're good.
        return true;
    }

    if (this->queryCString[this->queryIdx] == ')') {
        return true;
    }

    for (unsigned p = 0; p <= currentPrecedence; ++p) {
        const char * const token = PRECEDENCE_TO_OPERATOR_TOKEN[p];
        if (strncmp(this->queryCString + this->queryIdx, token, strlen(token)) == 0) {
            return true;
        }
    }

    return false;
}

ROP::RegisterQueryX86::QueryNode*
ROP::RegisterQueryX86::parseQuery(unsigned currentPrecedence) {
    if (currentPrecedence == MAX_PRECEDENCE) {
        // We want to look for basic terms like "true" or "read(reg)" now.
        // We could also find a subquery in parenthesis here: "(expr)".

        if (this->queryCString[this->queryIdx] == '(') {
            this->queryIdx += 1; // Jump over '('.
            int newPrecedence = 0; // Start again.
            QueryNode *node = this->parseQuery(newPrecedence);

            if (node == NULL) {
                // Propagate the error.
                return NULL;
            }

            if (this->queryCString[this->queryIdx] != ')') {
                LogError("Didn't find expected ')' character at index %u when parsing register query.", this->queryIdx);

                // Free memory.
                this->freeTree(node);
                return NULL;
            }

            this->queryIdx += 1; // Jump over '('.
            return node;
        }
        else {
            // The query should contain a basic term now.
            QueryNode *node = this->parseQueryLeaf();
            return node;
        }
    }
    else if (PRECEDENCE_TO_OPERATOR_TYPE[currentPrecedence] == QueryNodeType::NOT_OPERATOR) {
        const char * const token = PRECEDENCE_TO_OPERATOR_TOKEN[currentPrecedence];
        size_t tokenSize = strlen(token);
        bool shouldNegate = false;

        // While the next character(s) represent the negation operator.
        while (strncmp(this->queryCString + this->queryIdx, token, tokenSize) == 0) {
            // Remember the operator and jump over it.
            shouldNegate = !shouldNegate;
            this->queryIdx += tokenSize;
        }

        // No more negation operators. Try to parse the query according to the next operator.
        QueryNode *node = this->parseQuery(currentPrecedence + 1);
        if (node == NULL) {
            // Propagate the error.
            return NULL;
        }

        if (shouldNegate) {
            QueryNode *negationNode = new QueryNode();
            negationNode->nodeType = QueryNodeType::NOT_OPERATOR;
            negationNode->unary.child = node;
            node = negationNode;
        }

        return node;
    }
    else {
        // We are looking for "subexpr1 CURRENT_OPERATOR subexpr2 CURRENT_OPERATOR subexpr3 ...".
        const char * const token = PRECEDENCE_TO_OPERATOR_TOKEN[currentPrecedence];
        size_t tokenSize = strlen(token);

        // Parse the first term (which can be a subexpression that uses operators with higher precedence).
        QueryNode *currentNode = this->parseQuery(currentPrecedence + 1);
        if (currentNode == NULL) {
            // Propagate the error.
            return NULL;
        }

        while (strncmp(this->queryCString + this->queryIdx, token, tokenSize) == 0) {
            // Jump over the operator characters.
            this->queryIdx += tokenSize;

            // Parse the next term (which can be a subexpression that uses operators with higher precedence).
            QueryNode *nextNode = this->parseQuery(currentPrecedence + 1);
            if (nextNode == NULL) {
                // Free memory and propagate the error.
                this->freeTree(currentNode);
                return NULL;
            }

            QueryNode *bothNode = new QueryNode();
            bothNode->nodeType = PRECEDENCE_TO_OPERATOR_TYPE[currentPrecedence];
            bothNode->binary.leftChild = currentNode;
            bothNode->binary.rightChild = nextNode;

            currentNode = bothNode;
        }

        if (!this->nextQueryCharacterIsValid(currentPrecedence)) {
            LogError("Found invalid character '%c' when parsing the register query at index %u.",
                     this->queryCString[this->queryIdx], this->queryIdx);

            // Free memory.
            this->freeTree(currentNode);
            return NULL;
        }

        return currentNode;
    }
}

ROP::RegisterQueryX86::RegisterQueryX86(const std::string queryString):
    queryString(GetLowercaseString(GetStringNoWhitespace(queryString))),
    queryCString(this->queryString.c_str())
{
    this->precomputeTermStrings();

    this->queryIdx = 0;
    this->queryTreeRoot = this->parseQuery(0);

    if (this->queryTreeRoot != NULL && this->queryIdx != this->queryString.size()) {
        // Some of the query string got parsed correctly, but not all of it => Bad query string.
        LogError("Found invalid character '%c' when parsing the register query at index %u.",
                 this->queryCString[this->queryIdx], this->queryIdx);

        this->freeTree(this->queryTreeRoot);
        this->queryTreeRoot = NULL;
    }
}


bool ROP::RegisterQueryX86::isValidQuery() const {
    return this->queryTreeRoot != NULL;
}

void ROP::RegisterQueryX86::transformInstrSeqsToEnablePartialRegisterPacking(
    std::vector<std::vector<ROP::RegisterInfo>>& regInfoSequences
) {
    std::vector<std::vector<x86_reg>> partialRegisterGroups = {
        {X86_REG_RAX, X86_REG_EAX, X86_REG_AX, X86_REG_AH, X86_REG_AL},
        {X86_REG_RBX, X86_REG_EBX, X86_REG_BX, X86_REG_BH, X86_REG_BL},
        {X86_REG_RCX, X86_REG_ECX, X86_REG_CX, X86_REG_CH, X86_REG_CL},
        {X86_REG_RDX, X86_REG_EDX, X86_REG_DX, X86_REG_DH, X86_REG_DL},
        {X86_REG_RSI, X86_REG_ESI, X86_REG_SI, X86_REG_SIL},
        {X86_REG_RDI, X86_REG_EDI, X86_REG_DI, X86_REG_DIL},
        {X86_REG_RBP, X86_REG_EBP, X86_REG_BP, X86_REG_BPL},
        {X86_REG_RSP, X86_REG_ESP, X86_REG_SP, X86_REG_SPL},
        {X86_REG_R8, X86_REG_R8D, X86_REG_R8W, X86_REG_R8B},
        {X86_REG_R9, X86_REG_R9D, X86_REG_R9W, X86_REG_R9B},
        {X86_REG_R10, X86_REG_R10D, X86_REG_R10W, X86_REG_R10B},
        {X86_REG_R11, X86_REG_R11D, X86_REG_R11W, X86_REG_R11B},
        {X86_REG_R12, X86_REG_R12D, X86_REG_R12W, X86_REG_R12B},
        {X86_REG_R13, X86_REG_R13D, X86_REG_R13W, X86_REG_R13B},
        {X86_REG_R14, X86_REG_R14D, X86_REG_R14W, X86_REG_R14B},
        {X86_REG_R15, X86_REG_R15D, X86_REG_R15W, X86_REG_R15B},
    };

    std::vector<std::bitset<X86_REG_ENDING>> partialRegisterMasks;
    for (auto regGroup : partialRegisterGroups) {
        std::bitset<X86_REG_ENDING> groupMask;

        for (x86_reg reg : regGroup) {
            groupMask.set(reg, true);
        }

        partialRegisterMasks.push_back(groupMask);
    }

    for (std::vector<RegisterInfo>& currRegInfoSeq : regInfoSequences) {
        for (RegisterInfo& currRegInfo : currRegInfoSeq) {
            for (auto& partialRegMask : partialRegisterMasks) {
                // If any partial register in the mask is read by this instruction, then
                // we consider all of the partial registers in the mask as being read by this instruction.
                if ((currRegInfo.rRegs & partialRegMask).count() != 0) {
                    currRegInfo.rRegs |= partialRegMask;
                }

                // If any partial register in the mask is written by this instruction, then
                // we consider all of the partial registers in the mask as being written by this instruction.
                if ((currRegInfo.wRegs & partialRegMask).count() != 0) {
                    currRegInfo.wRegs |= partialRegMask;
                }
            }
        }
    }
}

bool ROP::RegisterQueryX86::matchesRegisterInfo(QueryNode *currentNode,
                                                const RegisterInfo& regInfoAny,
                                                const RegisterInfo& regInfoAll) {
    // This method will get called a lot. `Switch` is faster than `if` when there are a lot of cases.
    switch (currentNode->nodeType) {
        case QueryNodeType::VALUE_TRUE: {
            return true;
        }
        case QueryNodeType::VALUE_FALSE: {
            return false;
        }
        case QueryNodeType::ANY_READ_REGISTER: {
            return regInfoAny.rRegs[currentNode->registerID];
        }
        case QueryNodeType::ALL_READ_REGISTER: {
            return regInfoAll.rRegs[currentNode->registerID];
        }
        case QueryNodeType::ANY_WRITE_REGISTER: {
            return regInfoAny.wRegs[currentNode->registerID];
        }
        case QueryNodeType::ALL_WRITE_REGISTER: {
            return regInfoAll.wRegs[currentNode->registerID];
        }
        case QueryNodeType::ANY_READ_MEMORY_OPERAND: {
            return regInfoAny.readsMemoryOperand;
        }
        case QueryNodeType::ALL_READ_MEMORY_OPERAND: {
            return regInfoAll.readsMemoryOperand;
        }
        case QueryNodeType::ANY_WRITE_MEMORY_OPERAND: {
            return regInfoAny.writesMemoryOperand;
        }
        case QueryNodeType::ALL_WRITE_MEMORY_OPERAND: {
            return regInfoAll.writesMemoryOperand;
        }
        case QueryNodeType::ANY_HAVE_IMMEDIATE_VALUE: {
            return regInfoAny.hasImmediateValue;
        }
        case QueryNodeType::ALL_HAVE_IMMEDIATE_VALUE: {
            return regInfoAll.hasImmediateValue;
        }
        case QueryNodeType::NOT_OPERATOR: {
            return !this->matchesRegisterInfo(currentNode->unary.child, regInfoAny, regInfoAll);
        }
        case QueryNodeType::EQUALS_OPERATOR: {
            return this->matchesRegisterInfo(currentNode->binary.leftChild, regInfoAny, regInfoAll) ==
                   this->matchesRegisterInfo(currentNode->binary.rightChild, regInfoAny, regInfoAll);
        }
        case QueryNodeType::NOT_EQUALS_OPERATOR: {
            return this->matchesRegisterInfo(currentNode->binary.leftChild, regInfoAny, regInfoAll) !=
                   this->matchesRegisterInfo(currentNode->binary.rightChild, regInfoAny, regInfoAll);
        }
        case QueryNodeType::AND_OPERATOR: {
            return this->matchesRegisterInfo(currentNode->binary.leftChild, regInfoAny, regInfoAll) &&
                   this->matchesRegisterInfo(currentNode->binary.rightChild, regInfoAny, regInfoAll);
        }
        case QueryNodeType::OR_OPERATOR: {
            return this->matchesRegisterInfo(currentNode->binary.leftChild, regInfoAny, regInfoAll) ||
                   this->matchesRegisterInfo(currentNode->binary.rightChild, regInfoAny, regInfoAll);
        }
        default: {
            exitError("Got invalid operator type for current node when computing result. Type: %i",
                      (int)currentNode->nodeType);
        }
    }
}

// Check if a positive or negative index fits inside a sequence with a given size
// and return the corresponding positive index;
static inline int ComputeActualIndex(const int idx, const int seqSize) {
    if (0 <= idx && idx < seqSize) {
        return idx;
    }
    else if (-seqSize <= idx && idx < 0) {
        return seqSize + idx;
    }
    return -1;
}

bool ROP::RegisterQueryX86::matchesRegisterInfoOfInstructionSequence(const std::vector<RegisterInfo>& regInfoSequence) {
    if (this->queryTreeRoot == NULL) {
        return true;
    }

    // Check if [this->intervalLeft, this->intervalRight] seems to be a coherent interval.
    bool differentSign = ((this->intervalLeft < 0) != (this->intervalRight < 0));
    assertMessage(differentSign ||
                  this->intervalLeft <= this->intervalRight,
                  "Query index interval isn't coherent: [%i, %i]", this->intervalLeft, this->intervalRight);

    // Compute concrete [left, right] indexes for this specific sequence;
    int left = ComputeActualIndex(this->intervalLeft, (int)regInfoSequence.size());
    int right = ComputeActualIndex(this->intervalRight, (int)regInfoSequence.size());
    if (left == -1 || right == -1 || left > right) {
        return false;
    }
    assert(left <= right &&
           (0 <= left && left < (int)regInfoSequence.size()) &&
           (0 <= right && right < (int)regInfoSequence.size()));

    std::vector<RegisterInfo> regInfoSeqCopy(regInfoSequence.begin() + left, regInfoSequence.begin() + right + 1);
    assert(regInfoSeqCopy.size() > 0);

    RegisterInfo regInfoAny = RegisterInfo::reduceRegInfoListWithOrOperator(regInfoSeqCopy);
    RegisterInfo regInfoAll = RegisterInfo::reduceRegInfoListWithAndOperator(regInfoSeqCopy);
    return this->matchesRegisterInfo(this->queryTreeRoot, regInfoAny, regInfoAll);
}


void ROP::RegisterQueryX86::getStringRepresentationOfQuery(const QueryNode *currentNode, std::string& repr) const {
    switch (currentNode->nodeType) {
        case QueryNodeType::VALUE_TRUE: {
            repr += "true";
            break;
        }
        case QueryNodeType::VALUE_FALSE: {
            repr += "false";
            break;
        }
        case QueryNodeType::ANY_READ_REGISTER: {
            repr += "anyread(";
            repr += InstructionConverter::convertCapstoneRegIdToString(currentNode->registerID);
            repr += ")";
            break;
        }
        case QueryNodeType::ALL_READ_REGISTER: {
            repr += "allread(";
            repr += InstructionConverter::convertCapstoneRegIdToString(currentNode->registerID);
            repr += ")";
            break;
        }
        case QueryNodeType::ANY_WRITE_REGISTER: {
            repr += "anywrite(";
            repr += InstructionConverter::convertCapstoneRegIdToString(currentNode->registerID);
            repr += ")";
            break;
        }
        case QueryNodeType::ALL_WRITE_REGISTER: {
            repr += "allwrite(";
            repr += InstructionConverter::convertCapstoneRegIdToString(currentNode->registerID);
            repr += ")";
            break;
        }
        case QueryNodeType::ANY_READ_MEMORY_OPERAND: {
            repr += "anyread(memory_operand)";
            break;
        }
        case QueryNodeType::ALL_READ_MEMORY_OPERAND: {
            repr += "allread(memory_operand)";
            break;
        }
        case QueryNodeType::ANY_WRITE_MEMORY_OPERAND: {
            repr += "anywrite(memory_operand)";
            break;
        }
        case QueryNodeType::ALL_WRITE_MEMORY_OPERAND: {
            repr += "allwrite(memory_operand)";
            break;
        }
        case QueryNodeType::ANY_HAVE_IMMEDIATE_VALUE: {
            repr += "anyhave(immediate_value)";
            break;
        }
        case QueryNodeType::ALL_HAVE_IMMEDIATE_VALUE: {
            repr += "allhave(immediate_value)";
            break;
        }
        case QueryNodeType::NOT_OPERATOR: {
            repr += "!(";
            this->getStringRepresentationOfQuery(currentNode->unary.child, repr);
            repr += ")";
            break;
        }
        case QueryNodeType::EQUALS_OPERATOR: {
            repr += "(";
            this->getStringRepresentationOfQuery(currentNode->binary.leftChild, repr);
            repr += " == ";
            this->getStringRepresentationOfQuery(currentNode->binary.rightChild, repr);
            repr += ")";
            break;
        }
        case QueryNodeType::NOT_EQUALS_OPERATOR: {
            repr += "(";
            this->getStringRepresentationOfQuery(currentNode->binary.leftChild, repr);
            repr += " != ";
            this->getStringRepresentationOfQuery(currentNode->binary.rightChild, repr);
            repr += ")";
            break;
        }
        case QueryNodeType::AND_OPERATOR: {
            repr += "(";
            this->getStringRepresentationOfQuery(currentNode->binary.leftChild, repr);
            repr += " && ";
            this->getStringRepresentationOfQuery(currentNode->binary.rightChild, repr);
            repr += ")";
            break;
        }
        case QueryNodeType::OR_OPERATOR: {
            repr += "(";
            this->getStringRepresentationOfQuery(currentNode->binary.leftChild, repr);
            repr += " || ";
            this->getStringRepresentationOfQuery(currentNode->binary.rightChild, repr);
            repr += ")";
            break;
        }
        default: {
            exitError("Got invalid operator type for current node when getting string representation. Type: %i",
                      (int)currentNode->nodeType);
        }
    }
}

std::string ROP::RegisterQueryX86::getStringRepresentationOfQuery() const {
    if (this->queryTreeRoot == NULL) {
        return "Bad query";
    }

    std::string repr;
    this->getStringRepresentationOfQuery(this->queryTreeRoot, repr);
    return repr;
}


void ROP::RegisterQueryX86::getGraphVizRepresentationOfQuery(
    const QueryNode *currentNode, std::string nameParent, std::string nameNode, std::ostringstream& repr
) const {
    std::string nameLeft = nameNode + "_L";
    std::string nameRight = nameNode + "_R";
    std::string nameDown = nameNode + "_D";
    std::string currLabel = "";

    switch (currentNode->nodeType) {
        case QueryNodeType::VALUE_TRUE: {
            currLabel = "true";
            break;
        }
        case QueryNodeType::VALUE_FALSE: {
            currLabel = "false";
            break;
        }
        case QueryNodeType::ANY_READ_REGISTER: {
            currLabel += "anyread(";
            currLabel += InstructionConverter::convertCapstoneRegIdToShortString(currentNode->registerID);
            currLabel += ")";
            break;
        }
        case QueryNodeType::ALL_READ_REGISTER: {
            currLabel += "allread(";
            currLabel += InstructionConverter::convertCapstoneRegIdToShortString(currentNode->registerID);
            currLabel += ")";
            break;
        }
        case QueryNodeType::ANY_WRITE_REGISTER: {
            currLabel += "anywrite(";
            currLabel += InstructionConverter::convertCapstoneRegIdToShortString(currentNode->registerID);
            currLabel += ")";
            break;
        }
        case QueryNodeType::ALL_WRITE_REGISTER: {
            currLabel += "allwrite(";
            currLabel += InstructionConverter::convertCapstoneRegIdToShortString(currentNode->registerID);
            currLabel += ")";
            break;
        }
        case QueryNodeType::ANY_READ_MEMORY_OPERAND: {
            currLabel = "anyread(memop)";
            break;
        }
        case QueryNodeType::ALL_READ_MEMORY_OPERAND: {
            currLabel = "allread(memop)";
            break;
        }
        case QueryNodeType::ANY_WRITE_MEMORY_OPERAND: {
            currLabel = "anywrite(memop)";
            break;
        }
        case QueryNodeType::ALL_WRITE_MEMORY_OPERAND: {
            currLabel = "allwrite(memop)";
            break;
        }
        case QueryNodeType::ANY_HAVE_IMMEDIATE_VALUE: {
            currLabel = "anyhave(imm)";
            break;
        }
        case QueryNodeType::ALL_HAVE_IMMEDIATE_VALUE: {
            currLabel = "allhave(imm)";
            break;
        }
        case QueryNodeType::NOT_OPERATOR: {
            currLabel = "!";
            this->getGraphVizRepresentationOfQuery(currentNode->unary.child, nameNode, nameDown, repr);
            break;
        }
        case QueryNodeType::EQUALS_OPERATOR: {
            currLabel = "==";
            this->getGraphVizRepresentationOfQuery(currentNode->binary.leftChild, nameNode, nameLeft, repr);
            this->getGraphVizRepresentationOfQuery(currentNode->binary.rightChild, nameNode, nameRight, repr);
            break;
        }
        case QueryNodeType::NOT_EQUALS_OPERATOR: {
            currLabel = "!=";
            this->getGraphVizRepresentationOfQuery(currentNode->binary.leftChild, nameNode, nameLeft, repr);
            this->getGraphVizRepresentationOfQuery(currentNode->binary.rightChild, nameNode, nameRight, repr);
            break;
        }
        case QueryNodeType::AND_OPERATOR: {
            currLabel = "&&";
            this->getGraphVizRepresentationOfQuery(currentNode->binary.leftChild, nameNode, nameLeft, repr);
            this->getGraphVizRepresentationOfQuery(currentNode->binary.rightChild, nameNode, nameRight, repr);
            break;
        }
        case QueryNodeType::OR_OPERATOR: {
            currLabel = "| |";
            this->getGraphVizRepresentationOfQuery(currentNode->binary.leftChild, nameNode, nameLeft, repr);
            this->getGraphVizRepresentationOfQuery(currentNode->binary.rightChild, nameNode, nameRight, repr);
            break;
        }
        default: {
            exitError("Got invalid operator type for current node when getting GraphViz representation. Type: %i",
                      (int)currentNode->nodeType);
        }
    }

    if (currentNode != this->queryTreeRoot) {
        repr << nameParent << " -> " << nameNode << "; ";
    }
    repr << nameNode << " [label = \"" << currLabel << "\"];\n";
}

std::string ROP::RegisterQueryX86::getGraphVizRepresentationOfQuery() const {
    if (this->queryTreeRoot == NULL) {
        return "Bad query";
    }

    std::ostringstream repr;
    this->getGraphVizRepresentationOfQuery(this->queryTreeRoot, "", "root", repr);
    return repr.str();
}


void ROP::RegisterQueryX86::freeTree(QueryNode *currentNode) {
    if (currentNode->nodeType == QueryNodeType::NOT_OPERATOR) {
        this->freeTree(currentNode->unary.child);
    }
    else if (currentNode->nodeType == QueryNodeType::EQUALS_OPERATOR ||
             currentNode->nodeType == QueryNodeType::NOT_EQUALS_OPERATOR ||
             currentNode->nodeType == QueryNodeType::AND_OPERATOR ||
             currentNode->nodeType == QueryNodeType::OR_OPERATOR) {
        this->freeTree(currentNode->binary.leftChild);
        this->freeTree(currentNode->binary.rightChild);
    }

    delete currentNode;
}

ROP::RegisterQueryX86::~RegisterQueryX86() {
    if (this->queryTreeRoot) {
        this->freeTree(this->queryTreeRoot);
    }
}