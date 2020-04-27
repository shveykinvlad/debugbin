all:	debugger traced threads clean
debugger:
		gcc -Wall main.c debuglib_64.c -o debugger
traced:
		nasm -f elf64 -o traced.o traced.asm
		ld -o traced traced.o
threads:
		gcc -Wall -pthread threads.c -o threads
clean:
		rm -f *.o



