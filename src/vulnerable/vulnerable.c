#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void printUserMessageVulnerableFread() {
    char localBuffer[100];

    // Read the message from the standard input (as fixed number of bytes).
    fread(localBuffer, 1, 400, stdin);

    printf("User message: %s\n", localBuffer);
}

void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
printUserMessageVulnerableFreadNoCanaries() {
    char localBuffer[100];

    // Read the message from the standard input (as fixed number of bytes).
    fread(localBuffer, 1, 400, stdin);

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
        printf("- The 'function' argument means which vulnerable code branch to take. Options: 'fread'.\n");
        printf("- Using further arguments or the standard input depends on the chosen 'function' argument.\n");
        exit(-1);
    }

    if (strcmp(argv[1], "fread") == 0) {
        printUserMessageVulnerableFreadNoCanaries();
    }
    else {
        printf("Got wrong 'function' CLI argument.\n");
        exit(-1);
    }

    return 0;
}
