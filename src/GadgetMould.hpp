#ifndef GADGET_MOULD_H
#define GADGET_MOULD_H

#include <map>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "VirtualMemoryInfo.hpp"

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"


// Forward declaration for friend function.
void testGadgetMouldConfiguration(std::string targetExecutable);


namespace ROP {
    class GadgetMould {
        private:

        bool isConfigured;

        // The name of the gadget, e.g. "assignConstant"
        std::string gadgetName;

        // The bytes that will end up on the payload stack when this gadget is instantiated.
        // It can contain padding and fixed values.
        // It can also contain irrelevant bytes that will be replaced with the arguments when instantiated.
        // The top of the stack is the first byte.
        byteSequence stackTemplate;

        // This tells us how many arguments this gadget has and where they are placed in the stack template.
        // The pair represents an inclusive [left, right] index interval.
        std::map<std::string, std::pair<unsigned,unsigned>> stackPositionForArgument;


        /* Assert that the inner structures are coherent. */
        void checkMouldFormatIsCoherent() const;

        /* Add an "arg" element from the XML to the mould when configuring it.
         * @param stackElement The "arg" stack element retrieved from the XML config document.
        */
        void addArgElemToMould(pugi::xml_node stackElement);

        /* Add an "insSeq" element from the XML to the mould when configuring it.
         * @param stackElement The "insSeq" stack element retrieved from the XML config document.
         * @param vmInfo The object representing the active virtual memory of the target process.
         *               This will be used to get the address of the instruction sequence.
         * @return If the operation was successful. This can fail if we can't find the instruction seq in the virtual memory.
        */
        bool addInsSeqElemToMould(pugi::xml_node stackElement, VirtualMemoryInfo& vmInfo);

        /* Assert that the given arguments match the inner structure of the mould. */
        void checkArgumentsFormatMatchesMouldFormat(const std::map<std::string, byteSequence>& arguments) const;


        public:

        /*
         * @return If the operation was successful.
         */
        bool configureMould(pugi::xml_node configDictionary, VirtualMemoryInfo& vmInfo);

        /* Insert the given arguments into the mould and get the bytes of the resulting gadget. */
        byteSequence getConcreteGadget(const std::map<std::string, byteSequence>& arguments) const;


        // So that it can access private data.
        friend void ::testGadgetMouldConfiguration(std::string targetExecutable);
    };
}


#endif // GADGET_MOULD_H
