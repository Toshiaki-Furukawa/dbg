CC = g++
LIBNAME = capstone
TESTLIB = gtest
FLAGS = -Wall -std=c++17

OBJECTS = build/dbg.o build/elf.o build/elftypes.o build/disass.o
ELF_OBJECTS = build/elf.o build/elftypes.o build/disass.o
DISASS_OBJECTS = build/disass.o

all: $(OBJECTS)
	#$(CC) dbg.cpp -o dbg -l $(LIBNAME) -Wall
	$(CC) $(OBJECTS) -o dbg -l $(LIBNAME) $(FLAGS)
#	gcc test/test.c -o test/test 

elf: $(ELF_OBJECTS)
	$(CC) $(ELF_OBJECTS) -o elf -Wall -l $(LIBNAME) $(FLAGS)

disass: $(DISASS_OBJECTS)
	$(CC) $(DISASS_OBJECTS) -o disass -Wall -l capstone

test_elf: $(ELF_OBJECTS) test/test_elf.o
	$(CC) $(ELF_OBJECTS) test/test_elf.o -o test/test_elf -l $(LIBNAME) -l $(TESTLIB) $(FLAGS)
	cd test && ./test_elf

test_disass: $(DISASS_OBJECTS) test/test_disass_i386.o test/test_disass_x86_64.o
	$(CC) $(DISASS_OBJECTS) test/test_disass_i386.o -o test/test_disass_i386 -l $(LIBNAME) -l $(TESTLIB) $(FLAGS)
	g++ $(DISASS_OBJECTS) test/test_disass_x86_64.o -o test/test_disass_x86_64 -l $(LIBNAME) -l $(TESTLIB) $(FLAGS)
	cd test && ./test_disass_i386 && ./test_disass_x86_64

# BUILDS
build/%.o: %.cpp
	$(CC) -c $< -o $@ $(FLAGS)


# TEST CASES
test/test_elf.o: test/test_elf.cpp
	$(CC) -c test/test_elf.cpp -o test/test_elf.o $(FLAGS)

test/test_i386.o: test/test_disass_i386.cpp
	$(CC) -c test/test_disass_i386.cpp -o test_disass_i386.o $(FLAGS)
	
test/test_x86_64.o: test/test_disass_x86_64.cpp
	$(CC) -c test/test_disass_i386.cpp -o test_disass_i386.o $(FLAGS)
	
examples:
	gcc examples/test.c -o examples/test_32 -m32
	gcc examples/test.c -o examples/test_64

clean:
	rm -f build/*
	rm -f test/*.o	
