#include "ELFParser.hpp"

#include <assert.h>
#include <filesystem>
#include <fstream>

#include "utils.hpp"

// (static method)
bool ROOP::ELFParser::elfPathIsAcceptable(const std::string& elfPath) {
    return (elfPath.size() != 0) && std::filesystem::exists(elfPath);
}

ROOP::ELFParser::ELFParser(const std::string& elfPath): elfPath(elfPath) {
    if (!ELFParser::elfPathIsAcceptable(elfPath)) {
        pv(elfPath); pn;
        exiterror("ELF file path should point to valid ELF file");
    }

    std::ifstream fin(elfPath, std::ifstream::binary);
    fin.seekg(0, std::ios_base::end);
    size_t bytesCount = fin.tellg();
    assert(bytesCount > 0);

    this->elfBytes.resize(bytesCount);

    fin.seekg(0, std::ios_base::beg);
    fin.read((char*)this->elfBytes.data(), bytesCount);

    pv(bytesCount); pn;
}
