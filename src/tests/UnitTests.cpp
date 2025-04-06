#include <assert.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <unistd.h>

#include "../common/utils.hpp"
#include "../InstructionConverter.hpp"
#include "../RegisterQueryX86.hpp"


using namespace std;
using namespace ROP;


void normalizeCWD() {
    string currentWorkingDirectory = filesystem::current_path();
    pv(currentWorkingDirectory); pn;

    printf("Setting CWD to the location of this binary...\n");
    SetCWDToExecutableLocation();

    currentWorkingDirectory = filesystem::current_path();
    pv(currentWorkingDirectory); pn;
}

void testRegisterQueryValidParse() {
    // Check that these strings are parsed successfully.
    vector<string> validQueryStrings = {
        "true",
        "false",
        "TRUE != FALSE",
        "read(RAX)",
        "anyread(RAX)",
        "allREAD(RAX)",
        "write(DH)",
        "anywrite(DH)",
        "ALLwrite(DH)",
        "allread(memop)",
        "anywrite(memory_operand)",
        "anyhave(imm)",
        "anyhave(immediate_value)",
        "allhave(immediate_value)",
        "((((read(RAX)))))",
        "!read(RAX)",
        "!(read(RAX))",
        "read(RAX) == (write(RAX))",
        "read(RAX) != (write(RAX))",
        "read(RAX) && (write(RAX))",
        "read(RAX) || (write(RAX))",
        "read(RAX   )   &&     (    write(RAX)  )",
        "!!(!(write(RBX))) == write(ECX) && (write(EDX) == write(ESP))",
        "!!(!(write(RBX))) != write(ECX) && (write(EDX) != write(ESP))",
        "!!!read(RAX) != !!!write(RAX) != !!!write(RBX)",
        "read(xmm0) || write(xmm1) || write(xmm2)",
        "!read(XMM0) && !!write(XMM1) != !!!write(XMM3) || !!(((!!write(XMM4))))",
        "(read(RAX) || READ(RBX)) && (WRITE(r8) != wRiTe(R15))",
        "   (read(RAX)||READ(RBX))  &&  (WRITE(r8)!=wRiTe(R15))   ",
        "   (read(RAX)||AnyRead(RBX))  &&  (WRITE(r8)!=anyWrite(R15))   ",
    };

    for (unsigned idx = 0; idx < validQueryStrings.size(); ++idx) {
        const auto &queryString = validQueryStrings[idx];
        if (!RegisterQueryX86(queryString).isValidQuery()) {
            LogError("Test #%i; Query string: \"%s\".", idx, queryString.c_str());
            LogError("RegisterQueryX86 parser fails on query string test that should be successful.");
            exit(-1);
        }
    }


    // Check that these strings are NOT parsed successfully.
    vector<string> invalidQueryStrings = {
        "()",
        "()()",
        "(false)(true)",
        "flase",
        "(read(RAX))(write(RBX))",
        "red(RAX)",
        "allred(RAX)",
        "read()",
        "read(reg)",
        "read(anything)",
        "write",
        "wrote(DH)",
        "everywrite(DH)",
        "allread(memory_op)", // It's "memop" or "memory_operand"
        "anywrite(mem_operand)",
        "))read(RAX)((",
        "read!(RAX)",
        "read(!RAX)",
        "read(RAX || RBX)",
        "write(RAX != RBX)",
        "read(RAX) ||",
        "!(read(RAX) &&)",
        "read(RAX) & write(RBX)",
        "read(RAX) AND write(RBX)",
        "read(xmm0, XMM1, XMM2)",
        "read(xmm0) ^ read(xmm1)",
        "read(xmm0) && && && read(xmm1)",
        "read(xmm0) && || read(xmm1)",
        "read(rax) || write(rbx)    ((",
        "read(rax) || write(rbx)    ))",
        "( read(rax) || write(rbx)",
        "(( read(rax) || write(rbx) )",
        ") read(rax) || write(rbx)",
    };

    for (unsigned idx = 0; idx < invalidQueryStrings.size(); ++idx) {
        const auto &queryString = invalidQueryStrings[idx];

        Log::ProgramLogLevel = Log::Level::None;
        RegisterQueryX86 rq(queryString);
        Log::ProgramLogLevel = Log::Level::Debug;

        if (rq.isValidQuery()) {
            LogError("Test #%i; Query string: \"%s\".", idx, queryString.c_str());
            LogError("RegisterQueryX86 parser succeeds on query string test that should fail.");
            exit(-1);
        }
    }
}


int main(int argc, char* argv[]) {
    UNUSED(argc); UNUSED(argv);
    Log::ProgramLogLevel = Log::Level::Debug;

    normalizeCWD(); LogLine();

    testRegisterQueryValidParse();
    LogInfo("All unit tests passed!");

    return 0;
}