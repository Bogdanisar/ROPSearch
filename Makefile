
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
