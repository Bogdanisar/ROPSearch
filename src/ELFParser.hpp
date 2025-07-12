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
        BitSizeClass fileBitType;
        byteSequence elfBytes;

        // The members of the 64bit structs are large enough to hold the data for the members of the 32bit structs as well,
        // so we just use the 64bit structs for both 32bit and 64bit ELF files.
        Elf64_Ehdr fileHeader;
        std::vector<Elf64_Phdr> segmentHeaders;
        std::vector<Elf64_Phdr> codeSegmentHeaders;
        std::vector<byteSequence> segmentBytes;
        std::vector<byteSequence> codeSegmentBytes;

        void readEntireBinaryIntoMemory(std::ifstream& fin);
        void readAndValidateFileHeader(std::ifstream& fin);
        void readSegments(std::ifstream& fin);

        public:
        static bool elfPathIsAcceptable(const std::string& elfPath);

        // Empty parser. Don't use this.
        // We need the default constructor to exist if we want
        // to be able to use std::map<key, ELFParser>.
        ELFParser();

        ELFParser(const std::string& elfPath);

        const std::string& getElfPath() const;
        const BitSizeClass& getFileBitType() const;
        const byteSequence& getElfBytes() const;
        const Elf64_Ehdr& getFileHeader() const;
        const std::vector<Elf64_Phdr>& getSegmentHeaders() const;
        const std::vector<Elf64_Phdr>& getCodeSegmentHeaders() const;
        const std::vector<byteSequence>& getSegmentBytes() const;
        const std::vector<byteSequence>& getCodeSegmentBytes() const;
    };

}


#endif // ELF_PARSER_H
