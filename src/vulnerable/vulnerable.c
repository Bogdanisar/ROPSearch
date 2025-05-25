#include <stdlib.h>
#include <stdio.h>
#include <string.h>


void printUserMessageVulnerable() {
    char localBuffer[100];

    // Read the message from the standard input (as 200 bytes).
    fread(localBuffer, 1, 200, stdin);

    printf("User message: %s\n", localBuffer);
}

int main(int argc, char* argv[]) {
    printf("argc = %i\n", argc);
    for (int i = 0; i < argc; ++i) {
        printf("argv[%i] = %s\n", i, argv[i]);
    }

    if (argc != 1) {
        printf("Usage: %s (Pass message in standard input)\n", argv[0]);
        exit(-1);
    }

    printUserMessageVulnerable();

    return 0;
}
