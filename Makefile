
bin/ROOP.exe: bin/ROOP.o bin/VirtualMemoryMapping.o bin/ELFParser.o
	g++ bin/ROOP.o bin/VirtualMemoryMapping.o bin/ELFParser.o -o bin/ROOP.exe

bin/ROOP.o: src/common/*.hpp src/ROOP.cpp
	g++ -Wall -Wextra -pedantic -c src/ROOP.cpp -o bin/ROOP.o

bin/VirtualMemoryMapping.o: src/common/*.hpp src/VirtualMemoryMapping.hpp src/VirtualMemoryMapping.cpp
	g++ -Wall -Wextra -pedantic -c src/VirtualMemoryMapping.cpp -o bin/VirtualMemoryMapping.o

bin/ELFParser.o: src/common/*.hpp src/ELFParser.cpp
	g++ -Wall -Wextra -pedantic -c src/ELFParser.cpp -o bin/ELFParser.o
