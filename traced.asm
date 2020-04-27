section    .text
    ; The _start symbol must be declared for the linker (ld)
    global _start

_start:

    ; Prepare arguments for the sys_write system call:
    ;   - rax: system call number (sys_write)
    ;   - rbx: file descriptor (stdout)
    ;   - rcx: pointer to string
    ;   - rdx: string length
    mov    rdx, len
    mov    rcx, msg
    mov    rbx, 1
    mov    rax, 4

    ; Execute the sys_write system call
    int    0x80

    ; Execute sys_exit
    mov    rax, 1
    int    0x80

section   .data
msg db    'Hello, world!', 0xa
len equ    $ - msg 
