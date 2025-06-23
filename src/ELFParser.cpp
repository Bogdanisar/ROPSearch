#include "ELFParser.hpp"

#include <assert.h>
#include <filesystem>
#include <fstream>

#include "common/utils.hpp"


#pragma region ELF types conversion
#if false
int ________ELF_types_conversion________;
#endif

static Elf64_Ehdr Convert32bitFileHeaderTo64Bit(Elf32_Ehdr fileHeader32) {
    Elf64_Ehdr fileHeader64;

    memcpy(fileHeader64.e_ident, fileHeader32.e_ident, EI_NIDENT);
    fileHeader64.e_type = fileHeader32.e_type;
    fileHeader64.e_machine = fileHeader32.e_machine;
    fileHeader64.e_version = fileHeader32.e_version;
    fileHeader64.e_entry = fileHeader32.e_entry;
    fileHeader64.e_phoff = fileHeader32.e_phoff;
    fileHeader64.e_shoff = fileHeader32.e_shoff;
    fileHeader64.e_flags = fileHeader32.e_flags;
    fileHeader64.e_ehsize = fileHeader32.e_ehsize;
    fileHeader64.e_phentsize = fileHeader32.e_phentsize;
    fileHeader64.e_phnum = fileHeader32.e_phnum;
    fileHeader64.e_shentsize = fileHeader32.e_shentsize;
    fileHeader64.e_shnum = fileHeader32.e_shnum;
    fileHeader64.e_shstrndx = fileHeader32.e_shstrndx;

    return fileHeader64;
}

static Elf64_Phdr Convert32bitSegmentHeaderTo64Bit(Elf32_Phdr segmentHeader32) {
    Elf64_Phdr segmentHeader64;

    segmentHeader64.p_type = segmentHeader32.p_type;
    segmentHeader64.p_flags = segmentHeader32.p_flags;
    segmentHeader64.p_offset = segmentHeader32.p_offset;
    segmentHeader64.p_vaddr = segmentHeader32.p_vaddr;
    segmentHeader64.p_paddr = segmentHeader32.p_paddr;
    segmentHeader64.p_filesz = segmentHeader32.p_filesz;
    segmentHeader64.p_memsz = segmentHeader32.p_memsz;
    segmentHeader64.p_align = segmentHeader32.p_align;

    return segmentHeader64;
}

#pragma endregion ELF types conversion



#pragma region Class implementation
#if false
int ________Class_implementation________;
#endif

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
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't move the stream object to the start of the file...");
    }

    unsigned char e_ident[EI_NIDENT];
    fin.read((char*)e_ident, sizeof(e_ident));
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't read e_ident[EI_NIDENT] from binary file...");
    }

    bool validMagic = e_ident[EI_MAG0] == ELFMAG0 &&
                      e_ident[EI_MAG1] == ELFMAG1 &&
                      e_ident[EI_MAG2] == ELFMAG2 &&
                      e_ident[EI_MAG3] == ELFMAG3;
    if (!validMagic) {
        pv(this->elfPath); pn;
        exitError("File is not valid ELF file (magic number)");
    }

    // Prepare to read the file header.
    fin.seekg(0, std::ios_base::beg);
    if (!fin) {
        pv(this->elfPath); pn;
        exitError("Can't move the stream object to the start of the file...");
    }

    // Read the file header.
    if (e_ident[EI_CLASS] == ELFCLASS64) {
        this->fileBitType = BitSizeClass::BIT64;

        Elf64_Ehdr fileHeader64;
        fin.read((char*)&fileHeader64, sizeof(fileHeader64));
        if (!fin) {
            pv(this->elfPath); pn;
            exitError("Can't read the Elf64_Ehdr header from the ELF file...");
        }

        this->fileHeader = fileHeader64;
    }
    else if (e_ident[EI_CLASS] == ELFCLASS32) {
        this->fileBitType = BitSizeClass::BIT32;

        Elf32_Ehdr fileHeader32;
        fin.read((char*)&fileHeader32, sizeof(fileHeader32));
        if (!fin) {
            pv(this->elfPath); pn;
            exitError("Can't read the Elf32_Ehdr header from the ELF file...");
        }

        this->fileHeader = Convert32bitFileHeaderTo64Bit(fileHeader32);
    }
    else {
        pv(this->elfPath); pn;
        exitError("Expected 32bit or 64bit ELF file but found invalid EI_CLASS: %hhu", e_ident[EI_CLASS]);
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
        union {
            Elf64_Phdr progHeader64;
            Elf32_Phdr progHeader32;
        } currProgramHeaderBytes;

        fin.read((char*)&currProgramHeaderBytes, programHeaderSize);
        if (!fin) {
            pv(this->elfPath); pn;
            exitError("Can't read the current program header in the ELF file...");
        }

        Elf64_Phdr currentProgHeader;
        if (this->fileBitType == BitSizeClass::BIT64) {
            assert(programHeaderSize == sizeof(Elf64_Phdr));
            currentProgHeader = currProgramHeaderBytes.progHeader64;
        }
        else {
            assert(this->fileBitType == BitSizeClass::BIT32);

            assert(programHeaderSize == sizeof(Elf32_Phdr));
            currentProgHeader = Convert32bitSegmentHeaderTo64Bit(currProgramHeaderBytes.progHeader32);
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

const ROP::BitSizeClass& ROP::ELFParser::getFileBitType() const {
    return this->fileBitType;
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


#pragma endregion Class implementation
