
.PHONY: all
all: bin/ROOP.exe bin/vulnerable.exe bin/vulnerableHelped.exe

wFlags := -Wall -Wextra -pedantic
KEYSTONE_LDFLAGS = -lkeystone -lstdc++ -lm


# "$@" is an automatic variable for the target name.


# Main code

bin/ROOP.exe: bin/ROOP.o bin/VirtualMemoryMapping.o bin/ELFParser.o bin/VirtualMemoryExecutableBytes.o
	g++ bin/ROOP.o bin/VirtualMemoryMapping.o bin/ELFParser.o bin/VirtualMemoryExecutableBytes.o $(KEYSTONE_LDFLAGS) -o $@

bin/ROOP.o: src/common/*.hpp src/ROOP.cpp
	g++ $(wFlags) -c src/ROOP.cpp -o $@

bin/VirtualMemoryMapping.o: src/common/*.hpp src/VirtualMemoryMapping.*
	g++ $(wFlags) -c src/VirtualMemoryMapping.cpp -o $@

bin/ELFParser.o: src/common/*.hpp src/ELFParser.*
	g++ $(wFlags) -c src/ELFParser.cpp -o $@

bin/VirtualMemoryExecutableBytes.o: src/common/*.hpp src/VirtualMemoryExecutableBytes.*
	g++ $(wFlags) -c src/VirtualMemoryExecutableBytes.cpp -o $@


# Vulnerable executable

bin/vulnerable.exe: bin/vulnerable.o
	gcc bin/vulnerable.o -o $@

bin/vulnerableHelped.exe: bin/vulnerable.o bin/hardcodedGadgets64bit.o
	gcc bin/vulnerable.o bin/hardcodedGadgets64bit.o -o $@

bin/vulnerable.o: src/vulnerable/vulnerable.c
	gcc $(wFlags) -O0 -c src/vulnerable/vulnerable.c -o $@

bin/hardcodedGadgets64bit.o: src/vulnerable/hardcodedGadgets64bit.c
	gcc $(wFlags) -O0 -c src/vulnerable/hardcodedGadgets64bit.c -o $@


.PHONY: clean
clean:
	rm -rf bin/*
