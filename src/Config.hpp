#ifndef Config_H
#define Config_H

#include <bitset>

#include "common/types.hpp"


namespace ROP {

    class Config {
        public:

        // Default value: 10.
        static int MaxInstructionsInInstructionSequence;

        /**
         * Include instruction sequences like "xor eax, eax; jmp 0xee877518 --> pop edi; pop esi; ret"
         * when listing them in the output.
         * Default value: true.
         */
        static bool SearchForSequencesWithDirectRelativeJumpsInTheMiddle;
        /**
         * Ignore instruction sequences like "jmp 0xee877518 --> pop edi; pop esi; ret"
         * when listing them in the output (since the starting `jmp` instruction doesn't add value by itself).
         * Default value: true.
         */
        static bool IgnoreOutputSequencesThatStartWithDirectRelativeJumps;

        // The assembly syntax that will be used by our instruction sequence tries and such.
        // Default value: AssemblySyntax::Intel.
        static AssemblySyntax innerAssemblySyntax;

        // Tell Capstone to compute the extra detail information when building the ins seq trie.
        // This isn't always needed.
        // Default value: false.
        static bool computeRegisterInfo;
    };

}


#endif // Config_H
