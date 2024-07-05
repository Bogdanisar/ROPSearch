#include "VirtualMemoryMapping.hpp"

#include <fstream>
#include <sstream>
#include "common/utils.hpp"


void ROOP::VirtualMemorySegmentMapping::printSegment() const {
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
    if (!fin) {
        pv(processPid); pv(mapsPath); pn;
        exiterror("Got error when opening /proc/PID/maps file");
    }

    std::string line;
    while (std::getline(fin, line)) {

        VirtualMemorySegmentMapping vmsm;
        int readCharacters;
        int matched = sscanf(line.c_str(), "%llx-%llx %4c %llx %llu:%llu %llu %n",
                             &vmsm.startAddress, &vmsm.endAddress, vmsm.rights, &vmsm.offset,
                             &vmsm.deviceMajor, &vmsm.deviceMinor, &vmsm.inodeNumber, &readCharacters);

        if (matched != 7) {
            pv(line); pn;
            exiterror("Got error when parsing /maps segment line");
        }

        vmsm.rights[4] = '\0';
        vmsm.rightsMask = 0;
        if (vmsm.rights[0] == 'r') { vmsm.rightsMask |= (unsigned int)ROOP::VirtualMemorySegmentMapping::SegmentRights::READ; }
        if (vmsm.rights[1] == 'w') { vmsm.rightsMask |= (unsigned int)ROOP::VirtualMemorySegmentMapping::SegmentRights::WRITE; }
        if (vmsm.rights[2] == 'x') { vmsm.rightsMask |= (unsigned int)ROOP::VirtualMemorySegmentMapping::SegmentRights::EXECUTE; }
        if (vmsm.rights[3] == 'p') { vmsm.rightsMask |= (unsigned int)ROOP::VirtualMemorySegmentMapping::SegmentRights::PRIVATE; }

        vmsm.path = std::string(line.c_str() + readCharacters);

        this->segmentMaps.push_back(vmsm);
    }
};

const std::vector<ROOP::VirtualMemorySegmentMapping>& ROOP::VirtualMemoryMapping::getSegmentMaps() const {
    return this->segmentMaps;
}

void ROOP::VirtualMemoryMapping::printMapping() const {
    for (const VirtualMemorySegmentMapping& s : this->segmentMaps) {
        s.printSegment();
    }
}
