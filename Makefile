
.PHONY: all
all: bin/ROPSearch.exe bin/ManualTests.exe bin/UnitTests.exe vulnerable

wFlags := -Wall -Wextra -pedantic
KEYSTONE_LDFLAGS := -lkeystone -lstdc++ -lm
CAPSTONE_LDFLAGS := -l:libcapstone.a

# Optimization flags.
OPT_MAIN = -O3
OPT_VULN = -O0


# "$@" is an automatic variable for the target name.
# "$^" is an automatic variable for all prerequisites.
# "$<" is an automatic variable for the first prerequisite.


# Classes

bin/VirtualMemoryMapping.o: src/VirtualMemoryMapping.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/VirtualMemoryMapping.cpp -o $@

bin/ELFParser.o: src/ELFParser.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/ELFParser.cpp -o $@

bin/VirtualMemoryExecutableBytes.o: src/VirtualMemoryExecutableBytes.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/VirtualMemoryExecutableBytes.cpp -o $@

bin/InstructionConverter.o: src/InstructionConverter.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/InstructionConverter.cpp -o $@

bin/InsSeqTrie.o: src/InsSeqTrie.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/InsSeqTrie.cpp -o $@

bin/VirtualMemoryInstructions.o: src/VirtualMemoryInstructions.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/VirtualMemoryInstructions.cpp -o $@

bin/Log.o: src/Log.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/Log.cpp -o $@

bin/RegisterQueryX86.o: src/RegisterQueryX86.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c src/RegisterQueryX86.cpp -o $@

classObjectFiles := bin/VirtualMemoryMapping.o bin/ELFParser.o bin/VirtualMemoryExecutableBytes.o \
				    bin/InstructionConverter.o bin/InsSeqTrie.o bin/VirtualMemoryInstructions.o \
					bin/Log.o bin/RegisterQueryX86.o


# Main program

bin/ROPSearch.o: src/ROPSearch.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c $< -o $@

bin/ROPSearch.exe: bin/ROPSearch.o $(classObjectFiles)
	g++ $(OPT_MAIN) $^ $(KEYSTONE_LDFLAGS) $(CAPSTONE_LDFLAGS) -o $@


# Tests code

bin/ManualTests.o: src/tests/ManualTests.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c $< -o $@

bin/ManualTests.exe: bin/ManualTests.o $(classObjectFiles)
	g++ $(OPT_MAIN) $^ $(KEYSTONE_LDFLAGS) $(CAPSTONE_LDFLAGS) -o $@

bin/UnitTests.o: src/tests/UnitTests.cpp $(shell find ./src -name "*.hpp")
	g++ $(wFlags) $(OPT_MAIN) -c $< -o $@

bin/UnitTests.exe: bin/UnitTests.o $(classObjectFiles)
	g++ $(OPT_MAIN) $^ $(KEYSTONE_LDFLAGS) $(CAPSTONE_LDFLAGS) -o $@


# Vulnerable executable
# Note: You can check if an executable was compiled with various protection settings if you run
#       $> checksec --file=yourExecutable.exe

bin/vulnerable32bit.o: src/vulnerable/vulnerable.c
	gcc -m32 -g $(wFlags) $(OPT_VULN) -c $< -o $@

bin/vulnerable64bit.o: src/vulnerable/vulnerable.c
	gcc -g $(wFlags) $(OPT_VULN) -c $< -o $@

bin/hardcodedGadgets64bit.o: src/vulnerable/hardcodedGadgets64bit.c
	gcc -g $(wFlags) $(OPT_VULN) -c $< -o $@


bin/vulnerable32bit.exe: bin/vulnerable32bit.o
	gcc -m32 $(OPT_VULN) $^ -o $@

bin/vulnerable64bit.exe: bin/vulnerable64bit.o
	gcc $(OPT_VULN) $^ -o $@

bin/vulnerableHelped64bit.exe: bin/vulnerable64bit.o bin/hardcodedGadgets64bit.o
	gcc $(OPT_VULN) $^ -o $@

.PHONY: vulnerable
vulnerable: bin/vulnerable32bit.exe bin/vulnerable64bit.exe bin/vulnerableHelped64bit.exe


# Misc

.PHONY: clean
clean:
	rm -rf bin/*
