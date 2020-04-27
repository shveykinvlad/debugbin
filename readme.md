# Debugger

**Compile**:\
gcc -m32 main.c debuglib.c -o debugger32\
gcc      main.c debuglib.c -o debugger

**Compile with nasm64**:\
nasm -f elf64 -o traced.o traced.asm\
ld -o traced traced.o

**Disassembly**:\
`bjdump -d name


