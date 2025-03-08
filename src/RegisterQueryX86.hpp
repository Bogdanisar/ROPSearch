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
         * Each node in the tree represents an operator.
         * The values are listed in the order of operator precedence, from highest precedence to lowest.
         * Leaf nodes are of "READ_REGISTER" or "WRITE_REGISTER" type.
         * The rest of the nodes in the tree are binary operators, with two child nodes
         * or a NOT operator, with one child node.
         */
        enum class QueryNodeType {
            READ_REGISTER,
            WRITE_REGISTER,
            NOT_OPERATOR,
            AND_OPERATOR,
            XOR_OPERATOR,
            OR_OPERATOR,
        };

        // A struct representing a node in the query expression tree. Each node corresponds to an operator.
        // Each subtree represents a subexpression of the whole expression.
        // Each tree/subtree can be evaluated to TRUE / FALSE based on given register information.
        struct QueryNode {
            QueryNodeType op;
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
        struct StoredRegisterOperatorString {
            // Something like "read(rax)" or "write(rax)".
            std::string regString;

            // Either QueryNodeType::READ_REGISTER or QueryNodeType::WRITE_REGISTER.
            QueryNodeType opType;

            // Something like X86_REG_RAX.
            x86_reg regID;
        };

        const std::string queryString;
        const char * const queryCString;
        std::vector<StoredRegisterOperatorString> registerOperatorStrings;
        unsigned queryIdx;
        QueryNode *queryTreeRoot;

        void precomputeRegisterOperatorStrings();
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
