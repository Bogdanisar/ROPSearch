#include "GadgetMould.hpp"

#include <algorithm>
#include <assert.h>


void ROP::GadgetMould::checkMouldFormatIsCoherent() const {

    for (const auto& [argname, position] : this->stackPositionForArgument) {

        // Check that left <= right for each [left,right] stack position interval.
        assertMessage(position.first <= position.second,
                      "[Gadget %s]: Stack position for argument '%s' is not increasing: [%u, %u]",
                      this->gadgetName.c_str(), argname.c_str(), position.first, position.second);

        // Check that each [left,right] stack position interval is within the content of the stack template.
        assertMessage(position.first < this->stackTemplate.size() && position.second < this->stackTemplate.size(),
                      "[Gadget %s]: Stack position for argument '%s', namely [%u, %u], is outside the stack template of size %u",
                      this->gadgetName.c_str(), argname.c_str(),
                      position.first, position.second, (unsigned)this->stackTemplate.size());
    }

    for (const auto& [argname1, position1] : this->stackPositionForArgument) {
        for (const auto& [argname2, position2] : this->stackPositionForArgument) {
            if (argname1 == argname2) {
                continue;
            }

            // Check that the stack intervals for different arguments don't overlap.
            assertMessage(position1.second < position2.first || position2.second < position1.first,
                          "[Gadget %s]: Stack position for arguments '%s' and '%s' overlap: [%u, %u] ^ [%u, %u]",
                          this->gadgetName.c_str(), argname1.c_str(), argname2.c_str(),
                          position1.first, position1.second, position2.first, position2.second);
        }
    }
}

static ROP::byteSequence convertAddressToByteSequence(unsigned long long address) {
    ROP::byteSequence ret;

    for (int i = 0; i < 8; ++i) {
        unsigned char byte = (address & 0xFF);
        ret.push_back(byte);

        address >>= 8;
    }

    if (!ROP::ROPConsts::architectureIsLittleEndian) {
        std::reverse(ret.begin(), ret.end());
    }

    return ret;
}

void ROP::GadgetMould::addArgElemToMould(pugi::xml_node stackElement) {
    pugi::xml_attribute nameAttr = stackElement.attribute("name");
    const char * const argName = nameAttr.as_string();
    assertMessage(!nameAttr.empty() && strcmp(argName, "") != 0,
                  "[Gadget %s]: Attribute 'name' of 'arg' XML node is malformed: \n%s",
                  this->gadgetName.c_str(), xmlNodeToString(stackElement).c_str());

    pugi::xml_attribute sizeAttr = stackElement.attribute("size");
    int argSize = sizeAttr.as_int(-1);
    assertMessage(!sizeAttr.empty() && argSize > 0,
                  "[Gadget %s]: Attribute 'size' of 'arg' XML node is malformed: \n%s",
                  this->gadgetName.c_str(), xmlNodeToString(stackElement).c_str());

    // Note the current [left, right] interval for this argument in the instance variable map.
    unsigned left = this->stackTemplate.size();
    unsigned right = left + argSize - 1;
    this->stackPositionForArgument[argName] = {left, right};

    // Insert some dummy bytes for this argument in the stack representation
    // (They will be replaced when the gadget mould becomes concrete).
    this->stackTemplate.insert(this->stackTemplate.end(), argSize, 0x00);
}

bool ROP::GadgetMould::addInsSeqElemToMould(pugi::xml_node stackElement, VirtualMemoryInfo& vmInfo) {
    pugi::xml_attribute syntaxAttr = stackElement.attribute("syntax");
    const char * const syntax = syntaxAttr.as_string();
    assertMessage(!syntaxAttr.empty() && strcmp(syntax, "") != 0,
                  "[Gadget %s]: Attribute 'syntax' of 'insSeq' XML node is malformed: \n%s",
                  this->gadgetName.c_str(), xmlNodeToString(stackElement).c_str());

    const char * const instructionsString = stackElement.child_value();
    const std::string instructionsAsm(instructionsString);
    printf("[Gadget %s]: Found instructions in XML: %s\n",
            this->gadgetName.c_str(), instructionsString); // TODO: Remove

    ROP::AssemblySyntax asmSyntax = ROP::AssemblySyntax::Intel;
    if (strcmp(syntax, "att") == 0) {
        asmSyntax = ROP::AssemblySyntax::ATT;
    }

    auto addressList = vmInfo.matchInstructionSequenceInVirtualMemory(std::string(instructionsString), asmSyntax);
    if (addressList.size() == 0) {
        printf("[Gadget %s]: Can't find in the virtual memory of the target program this instruction sequence: %s\n",
               this->gadgetName.c_str(), instructionsString);
        return false;
    }

    unsigned long long insSeqAddress = addressList[0];
    printf("[Gadget %s]: Found the instructions at this virtual memory address: 0x%016llX\n\n",
            this->gadgetName.c_str(), insSeqAddress); // TODO: Remove

    byteSequence addressBytes = convertAddressToByteSequence(insSeqAddress);
    this->stackTemplate.insert(this->stackTemplate.end(), addressBytes.begin(), addressBytes.end());

    return true;
}

bool ROP::GadgetMould::configureMould(pugi::xml_node configDict, VirtualMemoryInfo& vmInfo) {
    assertMessage(configDict, "Got NULL XML node when configuring mould");

    assertMessage(configDict.attribute("name"),
                  "'name' attribute doesn't exist in gadget XML: %s", xmlNodeToString(configDict).c_str());
    this->gadgetName = std::string(configDict.attribute("name").value());

    assertMessage(!configDict.children("variant").empty(),
                  "No <variant> nodes exist in gadget XML: %s", xmlNodeToString(configDict).c_str());
    for (pugi::xml_node variantNode : configDict.children("variant")) {

        // Get the child <stack> node for this current <variant> node.
        pugi::xml_node stackNode = variantNode.child("stack");
        assertMessage(stackNode,
                      "[Gadget %s]: <stack> node doesn't exist in gadget XML: %s",
                      this->gadgetName.c_str(), xmlNodeToString(variantNode).c_str());

        // Store the children of this <stack> node.
        std::vector<pugi::xml_node> allStackElements;
        for (pugi::xml_node stackElement : stackNode.children()) {
            if (stackElement.type() != pugi::xml_node_type::node_element) {
                continue;
            }

            allStackElements.push_back(stackElement);
        }

        // Reverse the order of the children of this <stack> node, if dictated by the 'stack-top' attribute.
        pugi::xml_attribute stackTopAttr = stackNode.attribute("stack-top");
        assertMessage(stackTopAttr,
                      "[Gadget %s]: 'stack-top' attribute doesn't exist in gadget XML: %s",
                      this->gadgetName.c_str(), xmlNodeToString(variantNode).c_str());

        bool topOfStackIsLast = strcmp(stackTopAttr.as_string(), "last") == 0;
        if (topOfStackIsLast) {
            std::reverse(allStackElements.begin(), allStackElements.end());
        }

        bool variantConfigWorked = true;

        // Iterate through the child nodes of this <stack> node
        // and update the mould information for each child we process.
        for (pugi::xml_node stackElement : allStackElements) {
            const char * const elemName = stackElement.name();

            if (strcmp(elemName, "arg") == 0) {
                this->addArgElemToMould(stackElement);
            }
            else if (strcmp(elemName, "insSeq") == 0) {
                if (!this->addInsSeqElemToMould(stackElement, vmInfo)) {
                    variantConfigWorked = false;
                    break;
                }
            }
            else {
                exiterror("[Gadget %s]: Found unexpected child node (%s) in this <stack> node: \n%s",
                          this->gadgetName.c_str(), elemName, xmlNodeToString(stackNode).c_str());
            }
        }

        if (variantConfigWorked) {
            this->isConfigured = true;
            break;
        }
        else {
            // Reset state and try again with the next variant.
            this->isConfigured = false;
            this->stackTemplate = {};
            this->stackPositionForArgument = {};
        }
    }

    if (this->isConfigured) {
        this->checkMouldFormatIsCoherent();
        return true;
    }
    else {
        return false;
    }
}

void ROP::GadgetMould::checkArgumentsFormatMatchesMouldFormat(const std::map<std::string, byteSequence>& arguments) const {
    // Check that the number of arguments is the same.
    assertMessage(this->stackPositionForArgument.size() == arguments.size(),
                  "[Gadget %s]: Wrong gadget instantiation. Num mould args: %u; Num instantiation arguments: %u",
                  this->gadgetName.c_str(), (unsigned)this->stackPositionForArgument.size(), (unsigned)arguments.size());

    for (const auto& [argname, position] : this->stackPositionForArgument) {
        // Check that the argument names match.
        assertMessage(arguments.find(argname) != arguments.end(),
                      "[Gadget %s]: Can't find mould argument '%s' in arguments array",
                      this->gadgetName.c_str(), argname.c_str());

        // Check that the size of each argument is the same.
        unsigned length = position.second - position.first + 1;
        assertMessage(length == arguments.at(argname).size(),
                      "[Gadget %s]: Wrong gadget instantiation. Arg '%s' has size %u, which doesn't match stack position: [%u, %u]",
                      this->gadgetName.c_str(), argname.c_str(),
                      (unsigned)arguments.at(argname).size(), position.first, position.second);
    }
}

ROP::byteSequence ROP::GadgetMould::getConcreteGadget(const std::map<std::string, byteSequence>& arguments) const {
    assertMessage(this->isConfigured, "Can't get concrete gadget for unconfigured gadget mould!");
    this->checkMouldFormatIsCoherent();
    this->checkArgumentsFormatMatchesMouldFormat(arguments);

    auto ret = this->stackTemplate;

    for (const auto& [argname, position] : this->stackPositionForArgument) {
        byteSequence bytes = arguments.at(argname);

        for (unsigned pos = position.first; pos <= position.second; ++pos) {
            ret[pos] = bytes[pos - position.first];
        }
    }

    return ret;
}
