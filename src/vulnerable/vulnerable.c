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
printUserMessageVulnerableFreadNoCanaries() {
    int32_t inputSize;
    char localBuffer[100];

    // Read the size of the input buffer;
    fread(&inputSize, sizeof(inputSize), 1, stdin);
    printf("Input size: %i\n", (int)inputSize);

    // Read the message from the standard input.
    // Not checking the size => Vulnerability.
    fread(localBuffer, 1, inputSize, stdin);

    printf("User message: %s\n", localBuffer);
}


int main(int argc, char* argv[]) {
    printf("argc = %i\n", argc);
    for (int i = 0; i < argc; ++i) {
        printf("argv[%i] = %s\n", i, argv[i]);
    }

    if (argc < 2) {
        printf("Usage: %s function ... \n", argv[0]);
        printf("Notes:\n");
        printf("- The 'function' argument means which vulnerable code branch to take. Options: 'safe', 'fread'.\n");
        printf("- Using further arguments or the standard input depends on the chosen 'function' argument.\n");
        exit(-1);
    }

    if (strcmp(argv[1], "safe") == 0) {
        printUserMessageSafe();
    }
    else if (strcmp(argv[1], "fread") == 0) {
        printUserMessageVulnerableFreadNoCanaries();
    }
    else {
        printf("Got wrong 'function' CLI argument.\n");
        exit(-1);
    }

    return 0;
}
