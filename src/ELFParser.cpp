#include "ELFParser.hpp"

#include <assert.h>
#include <filesystem>
#include <fstream>

#include "common/utils.hpp"

// (static method)
bool ROOP::ELFParser::elfPathIsAcceptable(const std::string& elfPath) {
    return (elfPath.size() != 0) && std::filesystem::exists(elfPath);
}


void ROOP::ELFParser::readEntireBinaryIntoMemory(std::ifstream& fin) {
    fin.seekg(0, std::ios_base::end);
    size_t bytesCount = fin.tellg();
    assert(bytesCount > 0);

    this->elfBytes.resize(bytesCount);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)this->elfBytes.data(), bytesCount);
    if (!fin) {
        pv(this->elfPath); pn;
        exiterror("Can't read binary file...");
    }
}

void ROOP::ELFParser::readAndValidateFileHeader(std::ifstream& fin) {
    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)this->fileHeader.e_ident, sizeof(this->fileHeader.e_ident));
    if (!fin) {
        pv(this->elfPath); pn;
        exiterror("Can't read e_ident[EI_NIDENT] from binary file...");
    }

    bool validMagic = this->fileHeader.e_ident[EI_MAG0] == ELFMAG0 &&
                      this->fileHeader.e_ident[EI_MAG1] == ELFMAG1 &&
                      this->fileHeader.e_ident[EI_MAG2] == ELFMAG2 &&
                      this->fileHeader.e_ident[EI_MAG3] == ELFMAG3;
    if (!validMagic) {
        pv(this->elfPath); pn;
        exiterror("File is not valid ELF file (magic number)");
    }

    bool is64BitELF = this->fileHeader.e_ident[EI_CLASS] == ELFCLASS64;
    if (!is64BitELF) {
        pv(this->elfPath); pn;
        exiterror("This tool only supports 64bit ELF files");
    }

    size_t entireFHSize = sizeof(this->fileHeader);
    size_t differenceFH = sizeof(this->fileHeader.e_ident);
    fin.read((char*)&this->fileHeader + differenceFH, entireFHSize - differenceFH);
    if (!fin) {
        pv(this->elfPath); pn;
        exiterror("Can't read the rest of Elf64_Ehdr header from ELF file...");
    }
}

ROOP::ELFParser::ELFParser(const std::string& elfPath): elfPath(elfPath) {
    if (!ELFParser::elfPathIsAcceptable(this->elfPath)) {
        pv(this->elfPath); pn;
        exiterror("ELF file path should point to valid ELF file");
    }

    std::ifstream fin(elfPath, std::ifstream::binary);
    this->readEntireBinaryIntoMemory(fin);
    this->readAndValidateFileHeader(fin);
}

const std::string& ROOP::ELFParser::getElfPath() const {
    return this->elfPath;
}

const std::vector<ROOP::byte>& ROOP::ELFParser::getElfBytes() const {
    return this->elfBytes;
}

const Elf64_Ehdr& ROOP::ELFParser::getFileHeader() const {
    return this->fileHeader;
}

const std::vector<Elf64_Phdr>& ROOP::ELFParser::getSegmentHeaders() const {
    return this->segmentHeaders;
}
