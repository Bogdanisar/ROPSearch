#include "VirtualMemoryExecutableBytes.hpp"

#include <algorithm>
#include <map>

#include "ELFParser.hpp"
#include <keystone/keystone.h>


ROOP::VirtualMemoryExecutableBytes::VirtualMemoryExecutableBytes(int processPid)
: vaSegmMapping(processPid) {
    // This is used as an optimization in case there are multiple executable segments for the same ELF path.
    // (Otherwise, we would need to create an ELFParser multiple times for the same path).
    std::map<std::string, ELFParser> elfPathToELFParser;

    const std::vector<VirtualMemorySegmentMapping>& allSegmentMaps = this->vaSegmMapping.getSegmentMaps();
    for (const VirtualMemorySegmentMapping& segmentMap : allSegmentMaps) {
        if (!ELFParser::elfPathIsAcceptable(segmentMap.path)) {
            continue;
        }

        bool isExecutable = (segmentMap.rightsMask & (unsigned int)ROOP::VirtualMemorySegmentMapping::SegmentRights::EXECUTE);
        if (!isExecutable) {
            continue;
        }

        if (elfPathToELFParser.count(segmentMap.path) == 0) {
            elfPathToELFParser[segmentMap.path] = ELFParser(segmentMap.path);
        }

        ELFParser& elfParser = elfPathToELFParser[segmentMap.path];
        const std::vector<Elf64_Phdr>& elfCodeSegmentHdrs = elfParser.getCodeSegmentHeaders();
        const std::vector<byteSequence>& elfCodeSegmentBytes = elfParser.getCodeSegmentBytes();
        for (size_t i = 0; i < elfCodeSegmentHdrs.size(); ++i) {
            const Elf64_Phdr& codeSegmHdr = elfCodeSegmentHdrs[i];
            const byteSequence& codeSegmBytes = elfCodeSegmentBytes[i];

            if ((Elf64_Off)segmentMap.offset != codeSegmHdr.p_offset) {
                continue;
            }

            VirtualMemoryExecutableSegment execSegm;
            execSegm.startVirtualAddress = segmentMap.startAddress;
            execSegm.endVirtualAddress = segmentMap.endAddress;
            execSegm.executableBytes = codeSegmBytes;
            this->executableSegments.push_back(execSegm);
        }
    }

    auto comparator = [](const VirtualMemoryExecutableSegment& a, const VirtualMemoryExecutableSegment& b){
        return a.startVirtualAddress < b.startVirtualAddress;
    };

    // They come sorted by default (from /proc/PID/maps), but just in case.
    std::sort(this->executableSegments.begin(), this->executableSegments.end(), comparator);
}

const ROOP::VirtualMemoryMapping& ROOP::VirtualMemoryExecutableBytes::getVASegmMapping() const {
    return this->vaSegmMapping;
}

const std::vector<ROOP::VirtualMemoryExecutableSegment>& ROOP::VirtualMemoryExecutableBytes::getExecutableSegments() const {
    return this->executableSegments;
}

bool ROOP::VirtualMemoryExecutableBytes::isValidVAAddressInExecutableSegment(unsigned long long vaAddress) const {
    for (const auto& execSegm : this->executableSegments) {
        if (execSegm.startVirtualAddress <= vaAddress && vaAddress < execSegm.endVirtualAddress) {
            return true;
        }
    }

    return false;
}

ROOP::byte ROOP::VirtualMemoryExecutableBytes::getByteAtVAAddress(unsigned long long vaAddress) const {
    for (const auto& execSegm : this->executableSegments) {

        // As far as I can tell, the difference between "end" and "actualEnd"
        // is that "end" must be a multiple of the page size.
        unsigned long long start = execSegm.startVirtualAddress;
        unsigned long long end = execSegm.endVirtualAddress;
        unsigned long long actualEnd = start + (unsigned long long)execSegm.executableBytes.size();

        if (start <= vaAddress && vaAddress < actualEnd) {
            return execSegm.executableBytes[vaAddress - start];
        }
        else if (start <= vaAddress && vaAddress < end) {
            return (byte)0;
        }
    }

    printf("Can't find the given virtual address in the loaded Virtual Memory of executable code!\n");
    printf("Bad address = %llu (0x%llx)\n", vaAddress, vaAddress);
    return (byte)0;
}

std::pair<ROOP::byteSequence, unsigned>
ROOP::VirtualMemoryExecutableBytes::convertInstructionSequenceToBytes(std::string instructionSequenceAsm, bool useATTAssemblySyntax) {
    byteSequence instructionSequence;

    ks_err err;
    ks_engine *ksEngine = NULL;
    const char * const insSeqCString = instructionSequenceAsm.c_str();
    unsigned char *insSeqEncoding = NULL;
    size_t insSeqEncodingSize;
    size_t numDecodedInstructions;

    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ksEngine);
    if (err != KS_ERR_OK) {
        printf("Keystone: ks_open() failed with error %u!\n", (unsigned)err);
        goto cleanup;
    }

    if (useATTAssemblySyntax) {
        // Convert the engine to use AT&T syntax
        err = ks_option(ksEngine, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
        if (err != KS_ERR_OK) {
            printf("Keystone: ks_option() failed with error %u!\n", (unsigned)err);
            goto cleanup;
        }
    }

    if (ks_asm(ksEngine, insSeqCString, 0, &insSeqEncoding, &insSeqEncodingSize, &numDecodedInstructions) != 0) {
        printf("Keystone: ks_asm() failed with error %u; Number of decoded instructions = %u;\n",
               (unsigned)ks_errno(ksEngine), (unsigned)numDecodedInstructions);
        goto cleanup;
    }

    for (size_t i = 0; i < insSeqEncodingSize; i++) {
        instructionSequence.push_back((byte)insSeqEncoding[i]);
    }

cleanup:
    // Free the bytes generated by Keystone.
    if (insSeqEncoding != NULL) {
        ks_free(insSeqEncoding);
    }

    // Close the Keystone instance.
    if (ksEngine != NULL) {
        ks_close(ksEngine);
    }

// Final
    if (instructionSequence.size() == 0) {
        pv(instructionSequenceAsm); pn;
        pv(numDecodedInstructions); pn;
        exiterror("Keystone conversion from instruction sequence string to instruction sequence bytes failed");
    }

    return {instructionSequence, numDecodedInstructions};
}

std::vector<unsigned long long>
ROOP::VirtualMemoryExecutableBytes::matchInstructionSequenceInVirtualMemory(ROOP::byteSequence instructionSequence) {
    assertMessage(instructionSequence.size() != 0, "Got empty instruction sequence...");

    std::vector<unsigned long long> matchedVirtualAddresses;

    for (const VirtualMemoryExecutableSegment& execSegm : this->executableSegments) {
        const byteSequence& segmentBytes = execSegm.executableBytes;
        int sizeCodeBytes = (int)segmentBytes.size();
        int sizeInsSeqBytes = (int)instructionSequence.size();

        for (int low = 0, high = sizeInsSeqBytes - 1; high < sizeCodeBytes; ++low, ++high) {
            bool match = true;
            for (int idx = 0; idx < sizeInsSeqBytes; ++idx) {
                if (instructionSequence[idx] != segmentBytes[low + idx]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                matchedVirtualAddresses.push_back(execSegm.startVirtualAddress + low);
            }
        }
    }

    return matchedVirtualAddresses;
}

std::vector<unsigned long long>
ROOP::VirtualMemoryExecutableBytes::matchInstructionSequenceInVirtualMemory(std::string instructionSequenceAsm, bool useATTAssemblySyntax) {
    auto ret = VirtualMemoryExecutableBytes::convertInstructionSequenceToBytes(instructionSequenceAsm, useATTAssemblySyntax);
    const byteSequence& instructionSequence = ret.first;
    return this->matchInstructionSequenceInVirtualMemory(instructionSequence);
}
