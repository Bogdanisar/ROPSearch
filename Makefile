
.PHONY: all
all: bin/ROOP.exe bin/vulnerable.exe bin/vulnerableHelped.exe


# Main code

bin/ROOP.exe: bin/ROOP.o bin/VirtualMemoryMapping.o bin/ELFParser.o bin/VirtualMemoryExecutableBytes.o
	g++ bin/ROOP.o bin/VirtualMemoryMapping.o bin/ELFParser.o bin/VirtualMemoryExecutableBytes.o -o bin/ROOP.exe

bin/ROOP.o: src/common/*.hpp src/ROOP.cpp
	g++ -Wall -Wextra -pedantic -c src/ROOP.cpp -o bin/ROOP.o

bin/VirtualMemoryMapping.o: src/common/*.hpp src/VirtualMemoryMapping.*
	g++ -Wall -Wextra -pedantic -c src/VirtualMemoryMapping.cpp -o bin/VirtualMemoryMapping.o

bin/ELFParser.o: src/common/*.hpp src/ELFParser.*
	g++ -Wall -Wextra -pedantic -c src/ELFParser.cpp -o bin/ELFParser.o

bin/VirtualMemoryExecutableBytes.o: src/common/*.hpp src/VirtualMemoryExecutableBytes.*
	g++ -Wall -Wextra -pedantic -c src/VirtualMemoryExecutableBytes.cpp -o bin/VirtualMemoryExecutableBytes.o


# Vulnerable executable

bin/vulnerable.exe: bin/vulnerable.o
	g++ bin/vulnerable.o -o bin/vulnerable.exe

bin/vulnerableHelped.exe: bin/vulnerable.o bin/hardcodedGadgets64bit.o
	g++ bin/vulnerable.o bin/hardcodedGadgets64bit.o -o bin/vulnerableHelped.exe

bin/vulnerable.o: src/vulnerable/vulnerable.c
	g++ -Wall -Wextra -pedantic -O0 -c src/vulnerable/vulnerable.c -o bin/vulnerable.o

bin/hardcodedGadgets64bit.o: src/vulnerable/hardcodedGadgets64bit.c
	g++ -Wall -Wextra -pedantic -O0 -c src/vulnerable/hardcodedGadgets64bit.c -o bin/hardcodedGadgets64bit.o


.PHONY: clean
clean:
	rm -rf bin/*
