#include "RegisterQueryX86.hpp"

#include <string.h>

#include "InstructionConverter.hpp"


static const char PRECEDENCE_TO_OPERATOR_CHAR[] = {'|', '^', '&', '!'};
static ROP::RegisterQueryX86::ExpressionOperator PRECEDENCE_TO_OPERATOR_TYPE[] = {
    ROP::RegisterQueryX86::ExpressionOperator::OR_OPERATOR,
    ROP::RegisterQueryX86::ExpressionOperator::XOR_OPERATOR,
    ROP::RegisterQueryX86::ExpressionOperator::AND_OPERATOR,
    ROP::RegisterQueryX86::ExpressionOperator::NOT_OPERATOR,
};

static const int MAX_PRECEDENCE = sizeof(PRECEDENCE_TO_OPERATOR_CHAR) / sizeof(PRECEDENCE_TO_OPERATOR_CHAR[0]);


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


void
ROP::RegisterQueryX86::precomputeRegisterOperatorStrings() {
    for (unsigned regIndex = 0; regIndex < (unsigned)X86_REG_ENDING; ++regIndex) {
        x86_reg regID = (x86_reg)regIndex;

        // Get a string like "X86_REG_RAX".
        const char *regCString = ROP::InstructionConverter::convertCapstoneRegIdToString(regID);

        // Keep only the part after the last '_' (e.g. just "RAX").
        regCString = strrchr(regCString, '_') + 1;

        for (const char * const op : {"read", "write"}) {
            // Get a string like "read(RAX)" or "write(RAX)".
            std::string currOperatorString = std::string(op) + "(" + std::string(regCString) + ")";

            // Turn to lowercase.
            for(char& c : currOperatorString) {
                c = tolower(c);
            }

            if (std::string(op) == "read") {
                this->registerOperatorStrings.push_back({currOperatorString, ExpressionOperator::READ_REGISTER, regID});
            }
            else {
                this->registerOperatorStrings.push_back({currOperatorString, ExpressionOperator::WRITE_REGISTER, regID});
            }
        }
    }
}

ROP::RegisterQueryX86::ExpressionNode*
ROP::RegisterQueryX86::parseLeafExpression() {
    // Check if the given expression is of the "read(REG)" type.
    for (const auto& regOperatorInfo : this->registerOperatorStrings) {
        const x86_reg& regID = regOperatorInfo.regID;
        const std::string& opString = regOperatorInfo.regString;
        const ExpressionOperator& exprOpType = regOperatorInfo.opType;

        if (strcmp(this->expressionCString, opString.c_str()) == 0) {
            // Go over the parsed string.
            this->exprIdx += (int)opString.size();

            // Create and return a corresponding node structure for the parsed expression.
            ExpressionNode *node = new ExpressionNode();
            node->op = exprOpType;
            node->registerID = regID;
            return node;
        }
    }

    LogError("Expected 'read(reg)' or 'write(reg)' when parsing register expression at index %u", this->exprIdx);
    return NULL;
}

bool
ROP::RegisterQueryX86::nextExpressionCharacterIsValid(unsigned currentPrecedence) {
    // This function is meant to be called after a term is parsed and the index is at the next character.
    // The next character is only valid if it corresponds to the operator for the current precedence
    // or the operators for lower precedences or the ')' character or the end of the string ('\0').
    // Otherwise, the expression string is malformed.

    if (this->exprIdx == this->expressionString.size() || this->expressionCString[this->exprIdx] == '\0') {
        // All the string got parsed correctly, so we're good.
        return true;
    }

    char ch = this->expressionCString[this->exprIdx];
    if (ch == ')' || ch == '\0') {
        return true;
    }

    for (unsigned p = 0; p <= currentPrecedence; ++p) {
        if (ch == PRECEDENCE_TO_OPERATOR_CHAR[p]) {
            return true;
        }
    }

    return false;
}

ROP::RegisterQueryX86::ExpressionNode*
ROP::RegisterQueryX86::parseExpression(unsigned currentPrecedence) {
    if (currentPrecedence == MAX_PRECEDENCE) {
        // We want to look for "read(reg)" or "write(reg)" now.
        // We could also find a subexpression in parenthesis here: "(expr)".

        if (this->expressionCString[this->exprIdx] == '(') {
            this->exprIdx += 1; // Jump over '('.
            int newPrecedence = 0; // Start again.
            ExpressionNode *node = this->parseExpression(newPrecedence);

            if (node == NULL) {
                // Propagate the error.
                return NULL;
            }

            if (this->expressionCString[this->exprIdx] != ')') {
                LogError("Didn't find expected ')' character at index %u when parsing register expression", this->exprIdx);
                return NULL;
            }

            this->exprIdx += 1; // Jump over '('.
            return node;
        }
        else {
            // The expression should be "read(reg)" or "write(reg)" now.
            ExpressionNode *node = this->parseLeafExpression();
            return node;
        }
    }
    else if (PRECEDENCE_TO_OPERATOR_TYPE[currentPrecedence] == ExpressionOperator::NOT_OPERATOR) {
        bool shouldNegate = false;

        // While the next character is the negation operator.
        while (this->expressionCString[this->exprIdx] == PRECEDENCE_TO_OPERATOR_CHAR[currentPrecedence]) {
            // Remember the operator and jump over it.
            shouldNegate = !shouldNegate;
            this->exprIdx += 1;
        }

        // No more negation operators. Try to parse the expression according to the next operator.
        ExpressionNode *node = this->parseExpression(currentPrecedence + 1);
        if (node == NULL) {
            // Propagate the error.
            return NULL;
        }

        if (shouldNegate) {
            ExpressionNode *negationNode = new ExpressionNode();
            negationNode->op = ExpressionOperator::NOT_OPERATOR;
            negationNode->unary.child = node;
            node = negationNode;
        }

        return node;
    }
    else {
        // We are looking for "subexpr1 | subexpr2 | subexpr3 ..." (if currentPrecedence == 0),
        // or similar for the other precedences.

        // Parse the first term (which can be a subexpression that uses operators with higher precedence).
        ExpressionNode *currentNode = this->parseExpression(currentPrecedence + 1);
        if (currentNode == NULL) {
            // Propagate the error.
            return NULL;
        }

        while (this->expressionCString[this->exprIdx] == PRECEDENCE_TO_OPERATOR_CHAR[currentPrecedence]) {
            // Parse the next term (which can be a subexpression that uses operators with higher precedence).
            ExpressionNode *nextNode = this->parseExpression(currentPrecedence + 1);
            if (nextNode == NULL) {
                // Propagate the error.
                return NULL;
            }

            ExpressionNode *bothNode = new ExpressionNode();
            bothNode->op = PRECEDENCE_TO_OPERATOR_TYPE[currentPrecedence];
            bothNode->binary.left = currentNode;
            bothNode->binary.right = nextNode;

            currentNode = bothNode;
        }

        if (!this->nextExpressionCharacterIsValid(currentPrecedence)) {
            LogError("Found invalid character '%c' when parsing the register expression at index %u",
                     this->expressionCString[this->exprIdx], this->exprIdx);
            return NULL;
        }

        return currentNode;
    }
}

ROP::RegisterQueryX86::RegisterQueryX86(const std::string expressionString):
    expressionString(GetLowercaseString(GetStringNoWhitespace(expressionString))),
    expressionCString(this->expressionString.c_str())
{
    // Compute value of `this->registerOperatorStrings`.
    this->precomputeRegisterOperatorStrings();

    // TODO: Rename expression to query.

    this->exprIdx = 0;
    this->expressionTreeRoot = this->parseExpression(0);
}
