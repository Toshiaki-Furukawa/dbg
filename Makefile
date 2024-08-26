CC = g++

all:
	$(CC) dbg.cpp -o dbg
	gcc test/test.c -o test/test
	
test:
	gcc test/test.c -o test/test
	
clean:
	rm test/test
	rm dbg
