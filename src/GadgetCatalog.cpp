#include "GadgetCatalog.hpp"

#include <algorithm>
#include <assert.h>


ROP::GadgetCatalog::GadgetCatalog(std::string xmlPath, VirtualMemoryInfo& vmInfo) {
    using namespace pugi;

    xml_document doc;
    xml_parse_result loadResult = doc.load_file(xmlPath.c_str());
    if (!loadResult) {
        pv(xmlPath); pn;
        exiterror("Got error '%s' at offset %llu loading the XML string",
                  loadResult.description(), (unsigned long long)loadResult.offset);
    }

    printf("XML document loaded!\n\n");

    xml_node catalog = doc.child("catalog");
    if (!catalog) {
        pv(xmlPath); pn;
        exiterror("Can't find <catalog> tag inside XML file: %s",
                  xmlNodeToString(doc).c_str());
    }

    xml_node gadgetNode;

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "assignConstant");
    this->gAssignConstant.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "assignVarToVar");
    this->gAssignVarToVar.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "storePointerDereferenceIntoVariable");
    this->gStorePointerDereferenceIntoVariable.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "storeVariableIntoPointerDereference");
    this->gStoreVariableIntoPointerDereference.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "negateValueOfVariable");
    this->gNegateValueOfVariable.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "incrementVariable");
    this->gIncrementVariable.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "decrementVariable");
    this->gDecrementVariable.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "addTwoVariables");
    this->gAddTwoVariables.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "subtractTwoVariables");
    this->gSubtractTwoVariables.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "multiplyTwoVariables");
    this->gMultiplyTwoVariables.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "divideTwoVariablesAndGetQuotient");
    this->gDivideTwoVariablesAndGetQuotient.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "divideTwoVariablesAndGetRemainder");
    this->gDivideTwoVariablesAndGetRemainder.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "callRegularFunctionWithRegisterArguments");
    this->gCallRegularFunctionWithRegisterArguments.configureMould(gadgetNode, vmInfo);

    gadgetNode = catalog.find_child_by_attribute("gadget", "name", "makeSystemCallWithRegisterArguments");
    this->gMakeSystemCallWithRegisterArguments.configureMould(gadgetNode, vmInfo);
}
