#include <stdlib.h>
#include <stdio.h>
#include <string.h>


// gcc src/vulnerable.c -o bin/vulnerable.exe && bin/vulnerable.exe "Test Message"


void printUserMessageVulnerable(char *msg) {
    char localBuffer[100];
    strcpy(localBuffer, msg);
    printf("User message: %s\n", localBuffer);
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: %s userMessage\n", argv[0]);
        exit(-1);
    }

    printUserMessageVulnerable(argv[1]);

    return 0;
}
