CC = g++
LIBS = -lcapstone -lreadline
TESTLIB = gtest
FLAGS = -Wall -std=c++20

OBJECTS = build/main.o build/dbg.o build/fmt.o build/dbgtypes.o build/elf.o build/elftypes.o build/disass.o
ELF_OBJECTS = build/elf.o build/elftypes.o build/disass.o build/fmt.o build/dbgtypes.o
DISASS_OBJECTS = build/disass.o build/fmt.o
DBG_OBJECTS = build/dbg.o build/dbgtypes.o build/elf.o build/elftypes.o build/disass.o  build/fmt.o

all: $(OBJECTS)
	$(CC) $(OBJECTS) -o wg  $(LIBS) $(FLAGS)

elf: $(ELF_OBJECTS)
	$(CC) $(ELF_OBJECTS) -o elf -Wall  $(LIBS) $(FLAGS)

disass: $(DISASS_OBJECTS)
	$(CC) $(DISASS_OBJECTS) -o disass -Wall -l capstone

test_elf: $(ELF_OBJECTS) test/test_elf.o
	$(CC) $(ELF_OBJECTS) test/test_elf.o -o test/test_elf  $(LIBS) -l $(TESTLIB) $(FLAGS)
	cd test && ./test_elf

test_disass: $(DISASS_OBJECTS) test/test_disass_i386.o test/test_disass_x86_64.o
	$(CC) $(DISASS_OBJECTS) test/test_disass_i386.o -o test/test_disass_i386  $(LIBS) -l $(TESTLIB) $(FLAGS)
	$(CC) $(DISASS_OBJECTS) test/test_disass_x86_64.o -o test/test_disass_x86_64  $(LIBS) -l $(TESTLIB) $(FLAGS)
	cd test && ./test_disass_i386 && ./test_disass_x86_64

test_dbg: $(DBG_OBJECTS) test/test_dbg.o
	$(CC) $(DBG_OBJECTS) test/test_dbg.o -o test/test_dbg  $(LIBS) -l $(TESTLIB) $(FLAGS)
	cd test && ./test_dbg

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

test/test_dbg.o: test/test_dbg.cpp
	$(CC) -c test/test_dbg.cpp -o test/test_dbg.o $(FLAGS)

	
examples:
	gcc examples/test.c -o examples/test_32 -m32
	gcc examples/test.c -o examples/test_64

clean:
	rm -f build/*
	rm -f test/*.o	
