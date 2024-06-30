
bin/ROOP.exe: bin/ROOP.o bin/VirtualMemoryMapping.o
	g++ bin/ROOP.o bin/VirtualMemoryMapping.o -o bin/ROOP.exe

bin/ROOP.o: src/ROOP.cpp
	g++ -Wall -Wextra -pedantic -c src/ROOP.cpp -o bin/ROOP.o

bin/VirtualMemoryMapping.o: src/VirtualMemoryMapping.hpp src/VirtualMemoryMapping.cpp
	g++ -Wall -Wextra -pedantic -c src/VirtualMemoryMapping.cpp -o bin/VirtualMemoryMapping.o
