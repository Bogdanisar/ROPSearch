
.PHONY: all
all: bin/ROPSearch.exe bin/ManualTests.exe bin/vulnerable.exe bin/vulnerableHelped.exe

wFlags := -Wall -Wextra -pedantic
KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm
CAPSTONE_LDFLAGS = -l:libcapstone.a


# "$@" is an automatic variable for the target name.
# "$^" is an automatic variable for all prerequisites.
# "$<" is an automatic variable for the first prerequisite.


# Classes

bin/VirtualMemoryMapping.o: src/VirtualMemoryMapping.* src/common/*.hpp
	g++ $(wFlags) -c src/VirtualMemoryMapping.cpp -o $@

bin/ELFParser.o: src/ELFParser.* src/common/*.hpp
	g++ $(wFlags) -c src/ELFParser.cpp -o $@

bin/VirtualMemoryInfo.o: src/VirtualMemoryInfo.* src/common/*.hpp
	g++ $(wFlags) -c src/VirtualMemoryInfo.cpp -o $@

bin/InstructionConverter.o: src/InstructionConverter.* src/common/*.hpp
	g++ $(wFlags) -c src/InstructionConverter.cpp -o $@

bin/InsSeqTrie.o: src/InsSeqTrie.*
	g++ $(wFlags) -c src/InsSeqTrie.cpp -o $@

bin/GadgetMould.o: src/GadgetMould.* src/common/*.hpp
	g++ $(wFlags) -c src/GadgetMould.cpp -o $@

bin/GadgetCatalog.o: src/GadgetCatalog.* src/common/*.hpp
	g++ $(wFlags) -c src/GadgetCatalog.cpp -o $@

bin/Log.o: src/Log.* src/common/*.hpp
	g++ $(wFlags) -c src/Log.cpp -o $@

classObjectFiles := bin/VirtualMemoryMapping.o bin/ELFParser.o bin/VirtualMemoryInfo.o \
				    bin/InstructionConverter.o bin/InsSeqTrie.o bin/GadgetMould.o bin/GadgetCatalog.o bin/Log.o


# Main program

bin/ROPSearch.exe: bin/ROPSearch.o $(classObjectFiles)
	g++ $^ $(KEYSTONE_LDFLAGS) $(CAPSTONE_LDFLAGS) -o $@

bin/ROPSearch.o: src/ROPSearch.cpp src/common/*.hpp
	g++ $(wFlags) -c $< -o $@


# Tests code

bin/ManualTests.exe: bin/ManualTests.o $(classObjectFiles)
	g++ $^ $(KEYSTONE_LDFLAGS) $(CAPSTONE_LDFLAGS) -o $@

bin/ManualTests.o: src/ManualTests.cpp src/common/*.hpp
	g++ $(wFlags) -c $< -o $@


# Vulnerable executable

bin/vulnerable.exe: bin/vulnerable.o
	gcc $^ -o $@

bin/vulnerableHelped.exe: bin/vulnerable.o bin/hardcodedGadgets64bit.o
	gcc $^ -o $@

bin/vulnerable.o: src/vulnerable/vulnerable.c
	gcc $(wFlags) -O0 -c $< -o $@

bin/hardcodedGadgets64bit.o: src/vulnerable/hardcodedGadgets64bit.c
	gcc $(wFlags) -O0 -c $< -o $@


# Misc

.PHONY: clean
clean:
	rm -rf bin/*
