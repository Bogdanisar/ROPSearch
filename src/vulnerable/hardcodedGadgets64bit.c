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
gcc -O0 -c src/vulnerable/hardcodedGadgets64bit.c -o bin/hardcodedGadgets64bit.o

// Check the assembly content of the output file
objdump --disassemble --disassembler-options="intel" bin/hardcodedGadgets64bit.o
objdump --disassemble --disassembler-options="AT&T" bin/hardcodedGadgets64bit.o

===================================== Terminal commands =====================================
*/



#pragma region Assignment operations
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

void storePointerDereferenceIntoVariable(void) {
    // RAX - address of first memory location (pointer variable)
    // RBX - address of second memory location (variable)
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

void storeVariableIntoPointerDereference(void) {
    // RAX - address of first memory location (pointer variable)
    // RBX - address of second memory location (variable)
    // **RAX <- *RBX (i.e. *Variable1 <- Variable2)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "pop %rbx;"
        "mov (%rax), %rax;"
        "mov (%rbx), %rbx;"
        "mov %rbx, (%rax);"
        "ret;"
    );
}

#pragma endregion Assignment operations



#pragma region Arithmetic operations
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
        "nop;" // For easier visual separation in the output
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



#pragma region Bitwise operations
#if false
int ________Bitwise_operations________;
#endif

void bitwiseNotOnVariable(void) {
    // RAX - address of memory location (variable)
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "notq (%rax);"
        "ret;"
    );
}

void bitwiseAndOnTwoVariables(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rbx;"
        "pop %rcx;"
        "mov (%rax), %rax;"
        "mov (%rbx), %rbx;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "and %rbx, %rax;"
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void bitwiseOrOnTwoVariables(void) {
    // RAX, RBX - addresses of input variables
    // RCX - address of output variable
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rbx;"
        "pop %rcx;"
        "mov (%rax), %rax;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "or (%rbx), %rax;"
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void bitwiseXorOnTwoVariables(void) {
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
        "mov (%rax), %rax;"
        "xor (%rbx), %rax;"
        "mov %rax, (%rcx);"
        "ret;"
    );
}

void rightShiftVariable(void) {
    // TODO: Add binary shifts?
}

#pragma endregion Bitwise operations



#pragma region Branching operations
#if false
int ________Branching_operations________;
#endif

// TODO

#pragma endregion Branching operations



#pragma region Call operations
#if false
int ________Call_operations________;
#endif

// Some references:
// https://stackoverflow.com/a/2538212
// https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI


void callRegularFunctionWithRegisterArguments(void) {
    // On x86-64 Linux, integers and pointer arguments of regular function calls
    // are passed in %rdi, %rsi, %rdx, %rcx, %r8 and %r9.
    // Extra such arguments are placed on the stack.

    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rdi;"
        "pop %rsi;"
        "pop %rdx;"
        "pop %rcx;"
        "pop %r8;"
        "pop %r9;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "mov (%rdi), %rdi;"
        "mov (%rsi), %rsi;"
        "mov (%rdx), %rdx;"
        "mov (%rcx), %rcx;"
        "mov (%r8), %r8;"
        "mov (%r9), %r9;"
        "pop %rax;" // Pop the address of the function to call
        "call *%rax;"
        "ret;"
    );

    // RAX - Call return value
    // R10 - Address of variable to hold the call return value.
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %r10;"
        "mov %rax, (%r10);"
        "ret;"
    );
}

void makeSystemCallWithRegisterArguments(void) {
    // On x86-64 Linux, the kernel system call interface
    // uses %rdi, %rsi, %rdx, %r10, %r8 and %r9 for integer and pointer arguments.
    // System calls take at most 6 arguments.

    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rdi;"
        "pop %rsi;"
        "pop %rdx;"
        "pop %r10;"
        "pop %r8;"
        "pop %r9;"
        "ret;"
    );

    __asm__(
        "nop;" // For easier visual separation in the output
        "mov (%rdi), %rdi;"
        "mov (%rsi), %rsi;"
        "mov (%rdx), %rdx;"
        "mov (%r10), %r10;"
        "mov (%r8), %r8;"
        "mov (%r9), %r9;"
        "ret;"
    );

    // RAX - Call return value
    // R10 - Address of variable to hold the call return value.
    __asm__(
        "nop;" // For easier visual separation in the output
        "pop %rax;" // Pop the system call number.
        "syscall;"
        "pop %r10;"
        "mov %rax, (%r10);"
        "ret;"
    );
}

#pragma endregion Call operations
