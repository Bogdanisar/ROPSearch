#ifndef REGISTER_QUERY_X86_H
#define REGISTER_QUERY_X86_H

#include <string>

#include <capstone/capstone.h>

#include "common/types.hpp"
#include "InstructionConverter.hpp"


// Forward declarations for friend functions.
void testRegisterQueryTransformation();


namespace ROP {

    /**
     * A class that codifies a register query expression like "read(RAX) | (read(RBX) & write(DH))".
     * The expression string is codified into a tree at construction for easy evaluation.
     * These register queries are used to filter instruction sequences.
     */
    class RegisterQueryX86 {

        public:
        /**
         * Each leaf node in the query expression tree represents a simple term.
         * Each internal node in the query expression tree represents a query operator.
         * Operator nodes can have two child nodes or just one child node (NOT).
         * The values are listed in the order of expression evaluation precedence,
         * from highest precedence to lowest precedence.
         */
        enum class QueryNodeType {
            // Leaf
            VALUE_TRUE,
            VALUE_FALSE,
            ANY_READ_REGISTER, // At least one instruction reads the register.
            ALL_READ_REGISTER, // All instructions (except the last one) read the register.
            ANY_WRITE_REGISTER, // At least one instruction writes to the register.
            ALL_WRITE_REGISTER, // All instructions (except the last one) write to the register.
            ANY_READ_MEMORY_OPERAND, // At least one instruction reads a memory operand (e.g. [rax + 0xf]).
            ALL_READ_MEMORY_OPERAND, // All instructions (except the last one) read a memory operand (e.g. [rax + 0xf]).
            ANY_WRITE_MEMORY_OPERAND, // At least one instruction writes to a memory operand (e.g. [rax + 0xf]).
            ALL_WRITE_MEMORY_OPERAND, // All instructions (except the last one) write to a memory operand (e.g. [rax + 0xf]).
            ANY_HAVE_IMMEDIATE_VALUE, // At least one instruction contains an immediate value (e.g. "mov rax, 0x10").
            ALL_HAVE_IMMEDIATE_VALUE, // All instructions (except the last one) contain an immediate value (e.g. "mov rax, 0x10").

            // Operator
            NOT_OPERATOR,
            EQUALS_OPERATOR,
            NOT_EQUALS_OPERATOR,
            AND_OPERATOR,
            OR_OPERATOR,
        };

        // A struct representing a node in the query expression tree.
        // Each subtree represents a subexpression of the whole expression.
        // Each tree/subtree can be evaluated to TRUE / FALSE based on given register information.
        struct QueryNode {
            QueryNodeType nodeType;
            union {
                // For READ(reg) or WRITE(reg) operators.
                x86_reg registerID;

                // For NOT operator.
                struct {
                    QueryNode *child;
                } unary;

                // For binary operators.
                struct {
                    QueryNode *leftChild, *rightChild;
                } binary;
            };
        };


        private:

        // Auxiliary structure to store the precomputed information below.
        struct StoredTermString {
            // Something like "read(rax)", "write(memory_operand)", "have(immediate_value)".
            std::string termString;

            /**
             * Possible values:
             * - QueryNodeType::ANY/ALL_READ_REGISTER;
             * - QueryNodeType::ANY/ALL_WRITE_REGISTER;
             * - QueryNodeType::ANY/ALL_READ_MEMORY_OPERAND;
             * - QueryNodeType::ANY/ALL_WRITE_MEMORY_OPERAND;
             * - QueryNodeType::ANY/ALL_HAVE_IMMEDIATE_VALUE;
             */
            QueryNodeType nodeType;
        };
        struct StoredRegisterTermString : StoredTermString {
            // Something like X86_REG_RAX.
            x86_reg regID;
        };

        const std::string queryString;
        const char * const queryCString;
        std::vector<StoredRegisterTermString> registerTermStrings;
        std::vector<StoredTermString> memoryOperandTermStrings;
        std::vector<StoredTermString> immediateValueTermStrings;
        unsigned queryIdx;
        QueryNode *queryTreeRoot;

        void precomputeTermStrings();
        QueryNode* parseQueryLeaf();
        bool nextQueryCharacterIsValid(unsigned currentPrecedence);
        QueryNode* parseQuery(unsigned currentPrecedence);

        /**
         * Compute the result of the query represented by the subtree of `currentNode`
         * evaluating `read(reg)` and `write(reg)` terms according to the `RegisterInfo` parameters.
         */
        bool matchesRegisterInfo(QueryNode *currentNode,
                                 const RegisterInfo& regInfoAny,
                                 const RegisterInfo& regInfoAll);

        /**
         * Get a string representing the query of the tree rooted at `currentNode` and place it in `repr`.
         */
        void getStringRepresentationOfQuery(const QueryNode *currentNode, std::string& repr);

        public:
        RegisterQueryX86(const std::string queryString);

        bool isValidQuery() const;

        /**
         * Normally, each partial register is considered a separate register by Capstone.
         * For example, terms read(RAX), read(EAX), read(AX), read(AH) or read(AL) will match different instruction sequences.
         * Calling this method causes all partial registers to be considered the same register.
         * In other words, read(EAX) will match instructions like "mov bx, ax" as well.
         */
        void transformInstrSeqsToEnablePartialRegisterPacking(std::vector<std::vector<ROP::RegisterInfo>>& regInfoSequences);

        /**
         * Compute the result of the query, evaluating `read(reg)` and `write(reg)` terms
         * according to the `RegisterInfo` objects of the instruction sequence.
         */
        bool matchesRegisterInfoOfInstructionSequence(const std::vector<RegisterInfo>& regInfoSequence);

        std::string getStringRepresentationOfQuery();

        void freeTree(QueryNode *currentNode);
        ~RegisterQueryX86();


        // Mark these functions as friends so that they can access private members.
        friend void ::testRegisterQueryTransformation();
    };

}


#endif // REGISTER_QUERY_X86_H
