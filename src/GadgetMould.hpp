#ifndef GADGET_MOULD_H
#define GADGET_MOULD_H

#include <map>
#include <vector>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "VirtualMemoryInfo.hpp"

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"


namespace ROOP {
    struct GadgetMould {
        bool isConfigured;

        // The name of the gadget, e.g. "AssignConstant"
        std::string gadgetName;

        // The bytes that will end up on the payload stack when this gadget is instantiated.
        // It can contain padding and fixed values.
        // It can also contain irrelevant bytes that will be replaced with the arguments when instantiated.
        // The top of the stack is the first byte.
        byteSequence stackTemplate;

        // This tells us how many arguments this gadget has and where they are placed in the stack template.
        // The pair represents an inclusive [left, right] index interval.
        std::map<std::string, std::pair<unsigned,unsigned>> stackPositionForArgument;

        void checkMouldFormatIsCoherent() const;
        void configureMould(pugi::xml_node configDictionary, VirtualMemoryInfo& insTrie);

        void checkArgumentsFormatMatchesMouldFormat(const std::map<std::string, byteSequence>& arguments) const;
        byteSequence getConcreteGadget(const std::map<std::string, byteSequence>& arguments) const;
    };
}


#endif // GADGET_MOULD_H
