#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <map>
#include <string>
#include <vector>

#include "common/types.hpp"


namespace ROOP {

    struct InstructionSequenceMatch {
        instructionSequence iSeq;
        std::string iSeqAsm;
        std::vector<unsigned long long> matchedAddressesInVA;
    };

    class ELFParser {
        std::string elfPath;
        std::vector<byte> elfBytes;
        Elf64_Ehdr fileHeader;
        std::vector<Elf64_Phdr> segmentHeaders;

        void readEntireBinaryIntoMemory(std::ifstream& fin);
        void readAndValidateFileHeader(std::ifstream& fin);

        public:
        static bool elfPathIsAcceptable(const std::string& elfPath);
        ELFParser(const std::string& elfPath);

        const std::string& getElfPath() const;
        const std::vector<byte>& getElfBytes() const;
        const Elf64_Ehdr& getFileHeader() const;
        const std::vector<Elf64_Phdr>& getSegmentHeaders() const;

        std::map<instructionSequence, InstructionSequenceMatch>
        matchInstructionSequencesInFile(std::vector<instructionSequence> instructionSequences);
    };

}


#endif // ELF_PARSER_H
