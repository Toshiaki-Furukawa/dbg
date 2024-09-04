CC = g++
LIBNAME = capstone
TESTLIB = gtest

all: build/elf.o build/dbg.o build/disass.o
	#$(CC) dbg.cpp -o dbg -l $(LIBNAME) -Wall
	g++ build/dbg.o buld/elf.o buld/disass.o -o dbg =Wall -l capstone
#	gcc test/test.c -o test/test 

elf: build/elf.o build/disass.o
	g++ build/elf.o build/disass.o -o elf -Wall -l capstone

disass: build/disass.o
	g++ build/disass.o -o disass -Wall -l capstone

build/disass.o: disass.cpp disass.hpp
	g++ -c disass.cpp -o build/disass.o -Wall

build/elf.o: elf.cpp elf.hpp
	g++ -c elf.cpp -o build/elf.o -Wall

build/dbg.o: dbg.cpp dbg.hpp
	g++ -c dbg.cpp -o build/dbg.o -Wall
	
#test_: build/elf.o build/dbg.o build/disass.o

test_disass: build/disass.o test/test_disass_i386.o
	g++ test/test_disass_i386.o build/disass.o -o test/test_disass -Wall -l capstone -l gtest	
	cd test && ./test_disass

test_elf: build/elf.o build/disass.o test/test_elf.o
	g++ build/disass.o build/elf.o test/test_elf.o -o test/test_elf -Wall -l capstone -l gtest
	cd test && ./test_elf

test/test_elf.o: test/test_elf.cpp
	g++ -c test/test_elf.cpp -o test/test_elf.o -Wall	
	
test/test_i386.o: test/test_disass_i386.cpp
	g++ -c test/test_disass_i386.cpp -o test_disass_i386.o -Wall
	
	
examples:
	gcc examples/test.c -o examples/test_32 -m32
	gcc examples/test.c -o examples/test_64

clean:
	rm build/*
	
