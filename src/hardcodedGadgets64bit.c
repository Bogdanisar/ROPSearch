/*
This file is intentionally filled with (somewhat arbitrary) instruction sequences that can be used to
build a Turing-Complete set of gadgets to be used in Return-oriented-programming.
Each function represents the instruction sequences associated with a given gadget in the set.

The Turing-Complete set will use the memory-to-memory paradigm, meaning the inputs and ouputs
of all operations (e.g. of addition) will be memory locations ("variables" in ROP code).
Registers will be used as temporary locations to perform the necessary operations.

Note: gcc uses AT&T syntax by default so the assembly instructions are written in AT&T syntax.

Note: These functions are not supposed to be called in regular x86-64 code!
      (since they aren't necessarily coherent as x86-64 code when taken as a whole).
*/


/*
===================================== Terminal commands =====================================

// Build object file
gcc -O0 -c src/hardcodedGadgets64bit.c -o bin/hardcodedGadgets64bit.o

// Check the assembly content of the output file
objdump --disassemble --disassembler-options="intel" bin/hardcodedGadgets64bit.o
objdump --disassemble --disassembler-options="AT&T" bin/hardcodedGadgets64bit.o

===================================== Terminal commands =====================================
*/



#pragma #region Assignment operations
#if false
int ________Assignment_operations________;
#endif

void assignConstantToVariable(void) {
    // RAX - Address of memory location (variable)
    // RBX - Constant value
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "mov %rbx, (%rax);"
        "ret;"
    );
}

void assignVariableToVariable(void) {
    // RAX - address of first memory location (variable)
    // RBX - address of second memory location (variable)
    // *RBX <- *RAX
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "mov (%rax), %rax;"
        "mov %rax, (%rbx);"
        "ret;"
    );
}

void assignVariableToVariableDereference(void) {
    // RAX - address of first memory location (variable)
    // RBX - address of second memory location (pointer variable)
    // *RBX <- **RAX (i.e. Variable1 <- *Variable2)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "mov (%rax), %rax;"
        "mov (%rax), %rax;"
        "mov %rax, (%rbx);"
        "ret;"
    );
}

#pragma endregion Arithmetic operations



#pragma #region Arithmetic operations
#if false
int ________Arithmetic_operations________;
#endif

void negateValueOfVariable(void) {
    // RAX - address of memory location (variable)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "mov (%rax), %rbx;"
        "neg %rbx;"
        "mov %rbx, (%rax);"
        "ret;"
    );

    // or this

    // RAX - address of memory location (variable)
    // RBX - working register
    // RCX - 0
    // *RAX <- (0 - *RAX)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "mov (%rax), %rbx;"
        "xor %rcx, %rcx;"
        "sub %rbx, %rcx;"
        "mov %rcx, (%rax);"
        "ret;"
    );
}

void incrementVariable(void) {
    // RAX - address of memory location (variable)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "incq (%rax);"
        "ret;"
    );
}

void decrementVariable(void) {
    // RAX - address of memory location (variable)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "decq (%rax);"
        "ret;"
    );
}

void addTwoVariables(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "pop %rcx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "mov (%rax), %rax;"
        "mov (%rbx), %rbx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "add %rbx, %rax;"
        "ret;"
    );

    __asm__(
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void subtractTwoVariables(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "pop %rcx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "mov (%rax), %rax;"
        "mov (%rbx), %rbx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "sub %rbx, %rax;"
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void multiplyTwoVariables(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rcx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "mov (%rax), %rax;"
        "mov (%rbx), %rbx;"
        "imul %rbx, %rax;" // RAX = truncate(RAX * RBX);
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void divideTwoVariablesAndGetQuotient(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "pop %rcx;"
        "mov (%rax), %rax;"
        "idivq (%rbx);" // RAX = RAX / *RBX (quotient); RDX = RAX % *RBX (remainder);
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void divideTwoVariablesAndGetRemainder(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "pop %rcx;"
        "mov (%rax), %rax;"
        "idivq (%rbx);" // RAX = RAX / *RBX (quotient); RDX = RAX % *RBX (remainder);
        "mov %rdx, (%rcx);"
        "ret;"
    );
}

#pragma endregion Arithmetic operations

