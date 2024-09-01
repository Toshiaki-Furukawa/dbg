CC = g++
LIBNAME = capstone
TESTLIB = gtest

all:
	$(CC) dbg.cpp -o dbg -l $(LIBNAME) -Wall
#	gcc test/test.c -o test/test 
	
tests:
	#compile
	$(CC) test/test_elf.cpp -o test/test_elf -l $(TESTLIB) -l $(LIBNAME)
	# run tests
	cd test/ && ./test_elf && cd ..
	#./test/test_elf
	
examples:
	gcc examples/test.c -o examples/test_32 -m32
	gcc examples/test.c -o examples/test_64

clean:
	rm test/test_elf
	rm dbg
	rm elf
	rm disass
