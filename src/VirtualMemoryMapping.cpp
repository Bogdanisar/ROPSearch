#include "VirtualMemoryMapping.hpp"

#include <fstream>
#include <sstream>
#include "common/utils.hpp"


void ROOP::VirtualMemorySegment::printSegment() const {
    printf("%llx-%llx %s %08llx %02llu:%02llu %-7llu %18c %s;",
           this->startAddress, this->endAddress, this->rights, this->offset,
           this->deviceMajor, this->deviceMinor, this->inodeNumber, ' ', this->path.c_str());
    printf("\n");

    // pv(this->rightsMask); pn;
}


ROOP::VirtualMemoryMapping::VirtualMemoryMapping(int processPid) {

    std::stringstream ss;
    ss << "/proc/" << processPid << "/maps";
    std::string mapsPath = ss.str();

    std::ifstream fin(mapsPath);
    std::string line;
    while (std::getline(fin, line)) {

        VirtualMemorySegment vms;
        int readCharacters;
        int matched = sscanf(line.c_str(), "%llx-%llx %4c %llx %llu:%llu %llu %n",
                             &vms.startAddress, &vms.endAddress, vms.rights, &vms.offset,
                             &vms.deviceMajor, &vms.deviceMinor, &vms.inodeNumber, &readCharacters);

        if (matched != 7) {
            pv(line); pn;
            exiterror("Got error when parsing /maps segment line");
        }

        vms.rights[4] = '\0';
        vms.rightsMask = 0;
        if (vms.rights[0] == 'r') { vms.rightsMask |= (unsigned int)ROOP::VirtualMemorySegment::SegmentRights::READ; }
        if (vms.rights[1] == 'w') { vms.rightsMask |= (unsigned int)ROOP::VirtualMemorySegment::SegmentRights::WRITE; }
        if (vms.rights[2] == 'x') { vms.rightsMask |= (unsigned int)ROOP::VirtualMemorySegment::SegmentRights::EXECUTE; }
        if (vms.rights[3] == 'p') { vms.rightsMask |= (unsigned int)ROOP::VirtualMemorySegment::SegmentRights::PRIVATE; }

        vms.path = std::string(line.c_str() + readCharacters);

        this->segments.push_back(vms);
    }
};

const std::vector<ROOP::VirtualMemorySegment>& ROOP::VirtualMemoryMapping::getSegments() const {
    return this->segments;
}

void ROOP::VirtualMemoryMapping::printSegments() const {
    for (const VirtualMemorySegment& s : this->segments) {
        s.printSegment();
    }
}
