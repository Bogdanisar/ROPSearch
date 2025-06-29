#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


// Just to have an example of a function that has bounded buffer writing and that is compiled with stack canaries.
void printUserMessageSafe() {
    char localBuffer[105];
    memset(localBuffer, 0, sizeof(localBuffer));

    // Read the message from the standard input.
    fread(localBuffer, 1, 100, stdin);

    printf("User message: %s\n", localBuffer);
}


void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
printUserMessageVulnerableFread() {
    uint32_t inputSize;
    char localBuffer[100];
    memset(localBuffer, 0x00, sizeof(localBuffer));

    // Read the size of the input buffer;
    fread(&inputSize, sizeof(inputSize), 1, stdin);
    printf("Input size: %u\n", (unsigned)inputSize);

    // Read the message from the standard input.
    // Not checking the size => Vulnerability.
    fread(localBuffer, 1, inputSize, stdin);

    printf("User message: %s\n", localBuffer);
}


void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
printUserMessageUpperCaseVulnerableStrcpy(const char * const userInput) {
    char inputCopy[100];
    memset(inputCopy, 0x00, sizeof(inputCopy));

    // Make a copy of the input. No bounds check => Oops.
    strcpy(inputCopy, userInput);

    // Turn the copy to upper case.
    for (unsigned i = 0; i < sizeof(inputCopy); ++i) {
        inputCopy[i] = toupper(inputCopy[i]);
    }

    printf("Uppercase user message: %s\n", inputCopy);
}

void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
printUserMessageVulnerableStrcpyParent() {
    uint32_t inputSize;
    char userInput[1024];
    memset(userInput, 0x00, sizeof(userInput));

    // Read the size of the input buffer.
    fread(&inputSize, sizeof(inputSize), 1, stdin);
    printf("Input size: %u\n", (unsigned)inputSize);

    // Make sure the user input doesn't overflow the buffer.
    if (inputSize > sizeof(userInput) - 1) {
        inputSize = sizeof(userInput) - 1;
    }

    // Read the message from the standard input (safe).
    fread(userInput, 1, inputSize, stdin);
    printf("Initial user message: %s\n", userInput);

    printUserMessageUpperCaseVulnerableStrcpy(userInput);
}


int main(int argc, char* argv[]) {
    printf("argc = %i\n", argc);
    for (int i = 0; i < argc; ++i) {
        printf("argv[%i] = %s\n", i, argv[i]);
    }

    if (argc < 2) {
        printf("Usage: %s function ... \n", argv[0]);
        printf("Notes:\n");
        printf("- The 'function' argument means which vulnerable code branch to take. \n");
        printf("  Options: 'safe', 'fread', 'strcpy'.\n");
        printf("- Using further arguments or the standard input depends on the chosen 'function' argument.\n");
        exit(-1);
    }

    if (strcmp(argv[1], "safe") == 0) {
        printUserMessageSafe();
    }
    else if (strcmp(argv[1], "fread") == 0) {
        printUserMessageVulnerableFread();
    }
    else if (strcmp(argv[1], "strcpy") == 0) {
        printUserMessageVulnerableStrcpyParent();
    }
    else {
        printf("Got wrong 'function' CLI argument.\n");
        exit(-1);
    }

    return 0;
}
