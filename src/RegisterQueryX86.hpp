#ifndef REGISTER_QUERY_X86_H
#define REGISTER_QUERY_X86_H

#include <string>

#include <capstone/capstone.h>
#include "common/types.hpp"
#include "common/utils.hpp"

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
            READ_REGISTER,
            WRITE_REGISTER,

            // Operator
            NOT_OPERATOR,
            AND_OPERATOR,
            XOR_OPERATOR,
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
        struct StoredRegisterTermString {
            // Something like "read(rax)" or "write(rax)".
            std::string termString;

            // Either QueryNodeType::READ_REGISTER or QueryNodeType::WRITE_REGISTER.
            QueryNodeType nodeType;

            // Something like X86_REG_RAX.
            x86_reg regID;
        };

        const std::string queryString;
        const char * const queryCString;
        std::vector<StoredRegisterTermString> registerTermStrings;
        unsigned queryIdx;
        QueryNode *queryTreeRoot;

        void precomputeRegisterTermStrings();
        QueryNode* parseQueryLeaf();
        bool nextQueryCharacterIsValid(unsigned currentPrecedence);
        QueryNode* parseQuery(unsigned currentPrecedence);

        /**
         * Compute the result of the query represented by the subtree of `currentNode`
         * evaluating `read(reg)` and `write(reg)` operators according to the `registerInfo` parameter.
         */
        bool matchesRegisterInfo(QueryNode *currentNode, const RegisterInfo& registerInfo);

        /**
         * Get a string representing the query of the tree rooted at `currentNode` and place it in `repr`.
         */
        void getStringRepresentationOfQuery(const QueryNode *currentNode, std::string& repr);

        public:
        RegisterQueryX86(const std::string queryString);

        bool isValidQuery() const;

        /**
         * Compute the result of the query, evaluating `read(reg)` and `write(reg)` operators
         * according to the `registerInfo` parameter.
         */
        bool matchesRegisterInfo(const RegisterInfo& registerInfo);

        std::string getStringRepresentationOfQuery();

        void freeTree(QueryNode *currentNode);
        ~RegisterQueryX86();


        // Mark these functions as friends so that they can access private members.
        friend void ::testRegisterQueryTransformation();
    };

}


#endif // REGISTER_QUERY_X86_H
