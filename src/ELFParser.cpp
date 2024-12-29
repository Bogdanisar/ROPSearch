#include "ELFParser.hpp"

#include <assert.h>
#include <filesystem>
#include <fstream>

#include "common/utils.hpp"


// (static method)
bool ROP::ELFParser::elfPathIsAcceptable(const std::string& elfPath) {
    return (elfPath.size() != 0) && std::filesystem::exists(elfPath);
}


void ROP::ELFParser::readEntireBinaryIntoMemory(std::ifstream& fin) {
    fin.seekg(0, std::ios_base::end);
    size_t bytesCount = fin.tellg();
    assert(bytesCount > 0);

    this->elfBytes.resize(bytesCount);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)this->elfBytes.data(), bytesCount);
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't read binary file...");
    }
}

void ROP::ELFParser::readAndValidateFileHeader(std::ifstream& fin) {
    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)this->fileHeader.e_ident, sizeof(this->fileHeader.e_ident));
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't read e_ident[EI_NIDENT] from binary file...");
    }

    bool validMagic = this->fileHeader.e_ident[EI_MAG0] == ELFMAG0 &&
                      this->fileHeader.e_ident[EI_MAG1] == ELFMAG1 &&
                      this->fileHeader.e_ident[EI_MAG2] == ELFMAG2 &&
                      this->fileHeader.e_ident[EI_MAG3] == ELFMAG3;
    if (!validMagic) {
        pv(this->elfPath); pn;
        exitError("File is not valid ELF file (magic number)");
    }

    bool is64BitELF = this->fileHeader.e_ident[EI_CLASS] == ELFCLASS64;
    if (!is64BitELF) {
        pv(this->elfPath); pn;
        exitError("This tool only supports 64bit ELF files");
    }

    size_t entireFHSize = sizeof(this->fileHeader);
    size_t differenceFH = sizeof(this->fileHeader.e_ident);
    fin.read((char*)&this->fileHeader + differenceFH, entireFHSize - differenceFH);
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't read the rest of Elf64_Ehdr header from ELF file...");
    }
}

void ROP::ELFParser::readSegments(std::ifstream& fin) {
    Elf64_Off programHeaderTableOffset = this->fileHeader.e_phoff;
    Elf64_Half programHeaderSize = this->fileHeader.e_phentsize;
    Elf64_Half programHeaderNum = this->fileHeader.e_phnum;

    fin.seekg(programHeaderTableOffset, std::ios_base::beg);
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't seek to the begining of the program header table in the ELF file...");
    }

    // Load the program/segment headers.
    for (Elf64_Half i = 0; i < programHeaderNum; ++i) {
        Elf64_Phdr currentProgHeader;
        fin.read((char*)&currentProgHeader, programHeaderSize);
        if (!fin) {
            pv(this->elfPath); pn;
            exitError("Can't read the current program header in the ELF file...");
        }

        this->segmentHeaders.push_back(currentProgHeader);

        bool isLoadType = (currentProgHeader.p_type == PT_LOAD);
        bool isExecutable = ((currentProgHeader.p_flags & PF_X) != 0);
        bool hasLoadableFileContent = (currentProgHeader.p_filesz != 0);
        if (isLoadType && isExecutable && hasLoadableFileContent) {
            this->codeSegmentHeaders.push_back(currentProgHeader);
        }
    }

    // Now also load the bytes of the code segments.
    for (const Elf64_Phdr& codeProgHeader : this->codeSegmentHeaders) {
        auto segmentSizeInFile = codeProgHeader.p_filesz;

        byteSequence segmBytes;
        segmBytes.resize(segmentSizeInFile);

        fin.seekg(codeProgHeader.p_offset, std::ios_base::beg);
        fin.read((char*)segmBytes.data(), segmentSizeInFile);
        if (!fin) {
            pv(this->elfPath); pn;
            exitError("Can't read the bytes of the current code segment in the ELF file...");
        }

        if ((unsigned long long)segmBytes.size() != (unsigned long long)codeProgHeader.p_filesz) {
            LogWarn("loadedBytes.size() != codePH.p_filesz!");
        }

        this->codeSegmentBytes.push_back(segmBytes);
    }

    assert(this->codeSegmentHeaders.size() == this->codeSegmentBytes.size());
}

ROP::ELFParser::ELFParser() {}

ROP::ELFParser::ELFParser(const std::string& elfPath): elfPath(elfPath) {
    if (!ELFParser::elfPathIsAcceptable(this->elfPath)) {
        pv(this->elfPath); pn;
        exitError("ELF file path should point to valid ELF file");
    }

    std::ifstream fin(elfPath, std::ifstream::binary);
    this->readEntireBinaryIntoMemory(fin);
    this->readAndValidateFileHeader(fin);
    this->readSegments(fin);
}

const std::string& ROP::ELFParser::getElfPath() const {
    return this->elfPath;
}

const ROP::byteSequence& ROP::ELFParser::getElfBytes() const {
    return this->elfBytes;
}

const Elf64_Ehdr& ROP::ELFParser::getFileHeader() const {
    return this->fileHeader;
}

const std::vector<Elf64_Phdr>& ROP::ELFParser::getSegmentHeaders() const {
    return this->segmentHeaders;
}

const std::vector<Elf64_Phdr>& ROP::ELFParser::getCodeSegmentHeaders() const {
    return this->codeSegmentHeaders;
}

const std::vector<ROP::byteSequence>& ROP::ELFParser::getCodeSegmentBytes() const {
    return this->codeSegmentBytes;
}
