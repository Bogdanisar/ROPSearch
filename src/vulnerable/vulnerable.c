#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


char userInput[10000000];
unsigned userInputByteSize;

// Safe read of the user input from stdin.
void readUserInputSafely() {
    memset(userInput, 0x00, sizeof(userInput));

    // Read the first chunk of input (the payload),
    // but keep stdin open for subsequent reads (the commands for the shell).
    userInputByteSize = read(STDIN_FILENO, userInput, sizeof(userInput));
    printf("Bytes read from input = %u\n", userInputByteSize);
}


void printUppercaseVersionOfCString(char * const str, unsigned prefixSize) {
    for (unsigned idx = 0; idx < prefixSize; ++idx) {
        str[idx] = toupper(str[idx]);
    }
    printf("Uppercased input: %s\n", str);
}


void copyAndPrintUserMessageWithSafeMemcpy() {
    char inputCopy[100];
    memset(inputCopy, 0x00, sizeof(inputCopy));

    // Copy the message safely into the local buffer.
    memcpy(inputCopy, userInput, sizeof(inputCopy));

    printUppercaseVersionOfCString(inputCopy, sizeof(inputCopy));
}

void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
copyAndPrintUserMessageWithVulnerableMemcpy() {
    char inputCopy[100];
    memset(inputCopy, 0x00, sizeof(inputCopy));

    // Make a copy of the input.
    // Using the size of the source, not the destination => Oops.
    memcpy(inputCopy, userInput, userInputByteSize);

    printUppercaseVersionOfCString(inputCopy, sizeof(inputCopy));
}

void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
copyAndPrintUserMessageWithVulnerableStrcpy() {
    char inputCopy[100];
    memset(inputCopy, 0x00, sizeof(inputCopy));

    // Make a copy of the input.
    // No bounds check => Oops.
    strcpy(inputCopy, userInput);

    printUppercaseVersionOfCString(inputCopy, sizeof(inputCopy));
}

void
__attribute__ ((__optimize__ ("-fno-stack-protector")))
readAndPrintUserMessageWithVulnerableScanf() {
    char inputCopy[100];
    memset(inputCopy, 0x00, sizeof(inputCopy));

    // Make a copy of the input.
    // No bounds check => Oops.
    int numCharsReadByScanf;
    scanf("%s%n", inputCopy, &numCharsReadByScanf);
    printf("Number of bytes read by scanf() = %i\n", numCharsReadByScanf);

    printUppercaseVersionOfCString(inputCopy, sizeof(inputCopy));
}


int main(int argc, char* argv[]) {
    // printf("argc = %i\n", argc);
    // for (int i = 0; i < argc; ++i) {
    //     printf("argv[%i] = %s\n", i, argv[i]);
    // }

    if (argc != 2) {
        printf("Usage: %s function \n", argv[0]);
        printf("Notes:\n");
        printf("- The 'function' argument means which vulnerable code branch to take. \n");
        printf("  Options: 'safe', 'vulnerable_memcpy', 'vulnerable_strcpy', 'vulnerable_scanf'.\n");
        exit(-1);
    }

    if (strcmp(argv[1], "safe") == 0) {
        readUserInputSafely();
        copyAndPrintUserMessageWithSafeMemcpy();
    }
    else if (strcmp(argv[1], "vulnerable_memcpy") == 0) {
        readUserInputSafely();
        copyAndPrintUserMessageWithVulnerableMemcpy();
    }
    else if (strcmp(argv[1], "vulnerable_strcpy") == 0) {
        readUserInputSafely();
        copyAndPrintUserMessageWithVulnerableStrcpy();
    }
    else if (strcmp(argv[1], "vulnerable_scanf") == 0) {
        readAndPrintUserMessageWithVulnerableScanf();
    }
    else {
        printf("Got wrong 'function' CLI argument.\n");
        exit(-1);
    }

    return 0;
}
