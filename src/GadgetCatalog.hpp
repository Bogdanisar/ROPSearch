#ifndef GADGET_CATALOG_H
#define GADGET_CATALOG_H

#include <string>

#include "common/types.hpp"
#include "common/utils.hpp"
#include "GadgetMould.hpp"
#include "VirtualMemoryInfo.hpp"

#define PUGIXML_HEADER_ONLY
#include "../deps/pugixml/src/pugixml.hpp"


namespace ROP {

    /* This class contains a set ("catalog") of configured GadgetMould objects,
     * which can be used to instantiate arbitrary Return-oriented-programming "code".
     * The result of the code instantiation is a buffer-overflow payload for inserting into the vulnerable program.
     */
    class GadgetCatalog {
        GadgetMould gAssignConstant;
        GadgetMould gAssignVarToVar;
        GadgetMould gStorePointerDereferenceIntoVariable;
        GadgetMould gStoreVariableIntoPointerDereference;
        GadgetMould gNegateValueOfVariable;
        GadgetMould gIncrementVariable;
        GadgetMould gDecrementVariable;
        GadgetMould gAddTwoVariables;
        GadgetMould gSubtractTwoVariables;
        GadgetMould gMultiplyTwoVariables;
        GadgetMould gDivideTwoVariablesAndGetQuotient;
        GadgetMould gDivideTwoVariablesAndGetRemainder;
        GadgetMould gCallRegularFunctionWithRegisterArguments;
        GadgetMould gMakeSystemCallWithRegisterArguments;

        // TODO: Add bitwise gadgets
        // TODO: Add branching gadgets
        // TODO: Add ROP "code" instantiaton

        public:

        /*
         * @param xmlPath A file-system path to an XML config file for this catalog.
         * @param vmInfo An object representing the active virtual memory of the target process.
        */
        GadgetCatalog(std::string xmlPath, VirtualMemoryInfo& vmInfo);
    };
}


#endif // GADGET_CATALOG_H
