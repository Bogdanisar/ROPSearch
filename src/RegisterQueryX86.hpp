#ifndef REGISTER_QUERY_X86_H
#define REGISTER_QUERY_X86_H

#include <string>

#include <capstone/capstone.h>
#include "common/types.hpp"
#include "common/utils.hpp"


namespace ROP {

    /**
     * A class that codifies a register query expression like "read(RAX) | (read(RBX) & write(DH))".
     * The expression string is codified into a tree at construction for easy evaluation.
     * These register expressions are used to filter instruction sequences.
     */
    class RegisterQueryX86 {

        public:
        /**
         * Each node in the tree represents an operator.
         * The values are listed in the order of operator precedence, from highest precedence to lowest.
         * Leaf nodes are of "READ_REGISTER" or "WRITE_REGISTER" type.
         * The rest of the nodes in the tree are binary operators, with two child nodes
         * or a NOT operator, with one child node.
         */
        enum class ExpressionOperator {
            READ_REGISTER,
            WRITE_REGISTER,
            NOT_OPERATOR,
            AND_OPERATOR,
            XOR_OPERATOR,
            OR_OPERATOR,
        };

        // A struct representing a node in the expression tree. Each node corresponds to an operator.
        // Each subtree represents a subexpression of the whole expression.
        // Each tree/subtree can be evaluated to TRUE / FALSE based on given register information.
        struct ExpressionNode {
            ExpressionOperator op;
            union {
                // For READ(reg) or WRITE(reg) operators.
                x86_reg registerID;

                // For NOT operator.
                struct {
                    ExpressionNode *child;
                } unary;

                // For binary operators.
                struct {
                    ExpressionNode *left, *right;
                } binary;
            };
        };


        private:
        // Auxiliary structure to store the precomputed information below.
        struct StoredRegisterOperatorString {
            // Something like "read(rax)" or "write(rax)".
            std::string regString;

            // Either ExpressionOperator::READ_REGISTER or ExpressionOperator::WRITE_REGISTER.
            ExpressionOperator opType;

            // Something like X86_REG_RAX.
            x86_reg regID;
        };

        const std::string expressionString;
        const char * const expressionCString;
        std::vector<StoredRegisterOperatorString> registerOperatorStrings;
        unsigned exprIdx;
        ExpressionNode *expressionTreeRoot;

        void precomputeRegisterOperatorStrings();
        ExpressionNode* parseLeafExpression();
        bool nextExpressionCharacterIsValid(unsigned currentPrecedence);
        ExpressionNode* parseExpression(unsigned currentPrecedence);


        public:
        RegisterQueryX86(const std::string expressionString);

    };

}


#endif // REGISTER_QUERY_X86_H
