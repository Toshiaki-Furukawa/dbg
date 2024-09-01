CC = g++
LIBNAME = capstone

all:
	$(CC) dbg.cpp -o dbg -l $(LIBNAME) -Wall
	gcc test/test.c -o test/test 
	
test:
	gcc test/test.c -o test/test
	
clean:
	rm test/test
	rm dbg
