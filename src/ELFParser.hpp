#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <elf.h>
#include <map>
#include <string>
#include <vector>

#include "common/types.hpp"


namespace ROP {

    class ELFParser {
        std::string elfPath;
        byteSequence elfBytes;
        Elf64_Ehdr fileHeader;
        std::vector<Elf64_Phdr> segmentHeaders;
        std::vector<Elf64_Phdr> codeSegmentHeaders;
        std::vector<byteSequence> codeSegmentBytes;

        void readEntireBinaryIntoMemory(std::ifstream& fin);
        void readAndValidateFileHeader(std::ifstream& fin);
        void readSegments(std::ifstream& fin);

        public:
        static bool elfPathIsAcceptable(const std::string& elfPath);
        ELFParser(); // Empty parser. Don't use this.
        ELFParser(const std::string& elfPath);

        const std::string& getElfPath() const;
        const byteSequence& getElfBytes() const;
        const Elf64_Ehdr& getFileHeader() const;
        const std::vector<Elf64_Phdr>& getSegmentHeaders() const;
        const std::vector<Elf64_Phdr>& getCodeSegmentHeaders() const;
        const std::vector<byteSequence>& getCodeSegmentBytes() const;
    };

}


#endif // ELF_PARSER_H
