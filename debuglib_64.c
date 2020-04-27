/* Copyright 2017 Shveykin Vladislav */

#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>

#include <dirent.h>
#include <pthread.h>

#include "debuglib_64.h"

#if defined(__i386)
#define REGISTER_IP EIP
#define TRAP_LEN    1
#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFF00

#elif defined(__x86_64)
#define REGISTER_IP RIP
#define TRAP_LEN    1
#define TRAP_INST   0xCC
#define TRAP_MASK   0xFFFFFFFFFFFFFF00

#else
#error Unsupported architecture
#endif

struct breakpoint {
    void* addr;
    long orig_code;
    breakpoint *next;
} *head;

void procmsg(const char* format, ...) {
    va_list ap;
    fprintf(stdout, "[%d] ", getpid());
    va_start(ap, format);
    vfprintf(stdout, format, ap);
    va_end(ap);
}


void dbg_run_target(const char* programname) {
    procmsg("Target started. will run '%s'\n", programname);

    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        perror("ptrace");
        return;
    }
    execl(programname, programname, NULL);
}

uint64_t dbg_get_child_pc(pid_t pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    return regs.rip;
}

void* dbg_get_child_ip(pid_t pid) {
    long v = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*REGISTER_IP);
    return (void*) (v - TRAP_LEN);
}

long dbg_get_data(pid_t pid, void* addr) {
    long data = ptrace(PTRACE_PEEKTEXT, pid, addr);
    return data;
}

uint64_t dbg_get_reg(pid_t pid, char* reg) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (strcmp(reg, "r15") == 0) {
        return regs.r15;
    } else if (strcmp(reg, "r14") == 0) {
        return regs.r14;
    } else if (strcmp(reg, "r13") == 0) {
        return regs.r13;
    } else if (strcmp(reg, "r12") == 0) {
        return regs.r12;
    } else if (strcmp(reg, "rbp") == 0) {
        return regs.rbp;
    } else if (strcmp(reg, "rbx") == 0) {
        return regs.rbx;
    } else if (strcmp(reg, "r11") == 0) {
        return regs.r11;
    } else if (strcmp(reg, "r10") == 0) {
        return regs.r10;
    } else if (strcmp(reg, "r9") == 0) {
        return regs.r9;
    } else if (strcmp(reg, "r8") == 0) {
        return regs.r8;
    } else if (strcmp(reg, "rax") == 0) {
        return regs.rax;
    } else if (strcmp(reg, "rcx") == 0) {
        return regs.rcx;
    } else if (strcmp(reg, "rdx") == 0) {
        return regs.rdx;
    } else if (strcmp(reg, "rsi") == 0) {
        return regs.rsi;
    } else if (strcmp(reg, "rdi") == 0) {
        return regs.rdi;
    } else if (strcmp(reg, "orig_rax") == 0) {
        return regs.orig_rax;
    } else if (strcmp(reg, "rip") == 0) {
        return regs.rip;
    } else if (strcmp(reg, "cs") == 0) {
        return regs.cs;
    } else if (strcmp(reg, "ss") == 0) {
        return regs.ss;
    } else if (strcmp(reg, "rsp") == 0) {
        return regs.rsp;
    } else if (strcmp(reg, "fs_base") == 0) {
        return regs.fs_base;
    } else if (strcmp(reg, "gs_base") == 0) {
        return regs.gs_base;
    } else if (strcmp(reg, "ds") == 0) {
        return regs.ds;
    } else if (strcmp(reg, "es") == 0) {
        return regs.es;
    } else if (strcmp(reg, "fs") == 0) {
        return regs.fs;
    } else if (strcmp(reg, "gs") == 0) {
        return regs.fs;
    } else {
        printf("Undefined register: \"%s\"", reg);
        return -1;  //  register not found;
    }

    //  return regs.rip;
}

void* dbg_get_breakpoint_addr(breakpoint *bp) {
    return (void*) bp->addr;
}

void dbg_enable_breakpoint(pid_t pid, breakpoint *bp) {
    long orig = ptrace(PTRACE_PEEKTEXT, pid, bp->addr);
    ptrace(PTRACE_POKETEXT, pid, bp->addr, (orig & TRAP_MASK) | TRAP_INST);
    bp->orig_code = orig;
}

void dbg_disable_breakpoint(pid_t pid, breakpoint *bp) {
    ptrace(PTRACE_POKETEXT, pid, bp->addr, bp->orig_code);
}

breakpoint* dbg_add_breakpoint(breakpoint *head, pid_t pid, void* addr) {
    breakpoint *new = (breakpoint*)malloc(sizeof(breakpoint));
    new->addr = addr;
    new->next = head;
    head = new;
    dbg_enable_breakpoint(pid, head);
    return head;
}

breakpoint* dbg_delete_breakpoint(breakpoint *head, pid_t pid, void* addr) {
    breakpoint* prev = 0;
    breakpoint* temp = head;
    while (temp != NULL) {
        if (temp->addr == addr) {
            if (prev != NULL) {
                prev->next = temp->next;

            } else {
                head = temp->next;
            }
            dbg_disable_breakpoint(pid, temp);
            free(temp);
        }
        prev = temp;
        temp = temp->next;
    }
    return head;
}

breakpoint* dbg_clean_breakpoint(breakpoint *head) {
    while (head) {
        breakpoint* temp = head;
        head = head->next;
        free(temp);
    }
    return head;
}

breakpoint* dbg_get_breakpoint(breakpoint* head, void* addr) {
    while (head && (head->addr != addr)) {
        head = head->next;
    }

    return head;
}

void dbg_print_breakpoints(breakpoint* head) {
    breakpoint *ptr = head;
    printf("[ ");
    while (ptr != NULL) {
        printf("(%p) ", ptr->addr);
        ptr = ptr->next;
    }
    printf(" ]\n");
}

breakpoint *dbg_create_breakpoint(pid_t pid, void* addr) {
    breakpoint *bp = malloc(sizeof(*bp));
    bp->addr = addr;
    dbg_enable_breakpoint(pid, bp);
    return bp;
}

int dbg_resume_from_breakpoint(pid_t pid, breakpoint *bp) {
    int status = 1;
    /* 
        return 1 SIGTRAP, DEFAULT
        return 0 EXIT
        return -1 ERROR
    */
    if (bp) {
        ptrace(PTRACE_POKEUSER, pid, sizeof(long)*REGISTER_IP, bp->addr);

        dbg_disable_breakpoint(pid, bp);
        status = dbg_run(pid, PTRACE_SINGLESTEP);
        dbg_enable_breakpoint(pid, bp);
    }
    return status;
}

int dbg_run(pid_t pid, int cmd) {
    /* 
       return 1 SIGTRAP
       return 0 EXIT
       return -1 ERROR
    */
    int status, last_sig = 0, event;

    if (ptrace(cmd, pid, 0, last_sig) < 0) {
        perror("ptrace");
        return -1;
    }
    waitpid(pid, &status, 0);

    if (WIFEXITED(status))
        return 0;

    if (WIFSTOPPED(status)) {
        //  procmsg("STOPPED\n");
        last_sig = WSTOPSIG(status);
        //  printf("stopsig = %d\n", last_sig);
        if (last_sig == SIGTRAP) {
            event = (status >> 16) & 0xffff;
            return (event == PTRACE_EVENT_EXIT) ? 0 : 1;
        }
    }
    return 1;
}

size_t get_tids(pid_t **const listptr, size_t *const sizeptr, const pid_t pid) {
    char     dirname[64];
    DIR     *dir;
    pid_t   *list;
    size_t   size, used = 0;

    if (!listptr || !sizeptr || pid < (pid_t)1) {
        errno = EINVAL;
        return (size_t)0;
    }

    if (*sizeptr > 0) {
        list = *listptr;
        size = *sizeptr;
    } else {
        list = *listptr = NULL;
        size = *sizeptr = 0;
    }

    if (snprintf(dirname, sizeof dirname, "/proc/%d/task/", (int)pid) >= (int)sizeof dirname) {
        errno = ENOTSUP;
        return (size_t)0;
    }

    dir = opendir(dirname);
    if (!dir) {
        errno = ESRCH;
        return (size_t)0;
    }

    while (1) {
        struct dirent *ent;
        int            value;
        char           dummy;

        errno = 0;
        ent = readdir(dir);
        if (!ent)
            break;

        /* Parse TIDs. Ignore non-numeric entries. */
        if (sscanf(ent->d_name, "%d%c", &value, &dummy) != 1)
            continue;

        /* Ignore obviously invalid entries. */
        if (value < 1)
            continue;

        /* Make sure there is room for another TID. */
        if (used >= size) {
            size = (used | 127) + 128;
            list = realloc(list, size * sizeof list[0]);
            if (!list) {
                closedir(dir);
                errno = ENOMEM;
                return (size_t)0;
            }
            *listptr = list;
            *sizeptr = size;
        }

        /* Add to list. */
        list[used++] = (pid_t)value;
    }
    if (errno) {
        const int saved_errno = errno;
        closedir(dir);
        errno = saved_errno;
        return (size_t)0;
    }
    if (closedir(dir)) {
        errno = EIO;
        return (size_t)0;
    }

    /* None? */
    if (used < 1) {
        errno = ESRCH;
        return (size_t)0;
    }

    /* Make sure there is room for a terminating (pid_t)0. */
    if (used >= size) {
        size = used + 1;
        list = realloc(list, size * sizeof list[0]);
        if (!list) {
            errno = ENOMEM;
            return (size_t)0;
        }
        *listptr = list;
        *sizeptr = size;
    }

    /* Terminate list; done. */
    list[used] = (pid_t)0;
    errno = 0;
    return used;
}

int dbg_get_elf_header(const char* programname) {
    typedef struct elf64_hdr {
        unsigned char e_ident[16];      /* ELF "magic number" */
        Elf64_Half e_type;
        Elf64_Half e_machine;
        Elf64_Word e_version;
        Elf64_Addr e_entry;     /* Entry point virtual address */
        Elf64_Off e_phoff;      /* Program header table file offset */
        Elf64_Off e_shoff;      /* Section header table file offset */
        Elf64_Word e_flags;
        Elf64_Half e_ehsize;
        Elf64_Half e_phentsize;
        Elf64_Half e_phnum;
        Elf64_Half e_shentsize;
        Elf64_Half e_shnum;
        Elf64_Half e_shstrndx;
    } Elf64_Hdr;

    FILE* ElfFile = NULL;
    Elf64_Hdr hdr;

    ElfFile = fopen(programname, "rb");
    if (ElfFile == NULL) {
        perror("Failed to read elf header");
        return -1;
    }

    if (1 != fread(&hdr, sizeof(hdr), 1, ElfFile)) {
        fclose(ElfFile);
        perror("Failed to read elf header");
        return -1;
    }
    printf("ELF Header:\n");

    int i;
    printf("Magic:");
    for (i=0; i < 15; ++i)
        printf(" %x", hdr.e_ident[i]);
    printf("\n");

    char *class;
    switch (hdr.e_ident[EI_CLASS]) {
        case ELFCLASSNONE:
            class = "Inavalid Class";
            break;
        case ELFCLASS32:
            class = "32";
            break;
        case ELFCLASS64:
            class = "64";
            break;
        default:
            class = "";
    }
    printf("Class: %c%c%c%s\n", hdr.e_ident[EI_MAG1], hdr.e_ident[EI_MAG2],
            hdr.e_ident[EI_MAG3], class);

    switch (hdr.e_ident[EI_DATA]) {
        case ELFDATANONE:
            printf("Data: Invalid data encoding\n");
            break;
        case ELFDATA2LSB:
            printf("Data: 2's complement, little endian\n");
            break;
        case ELFDATA2MSB:
            printf("Data: 2's complement, big endian\n");
            break;
    }

    printf("Version: %d\n", hdr.e_version);

    switch (hdr.e_ident[EI_OSABI]) {
        case ELFOSABI_NONE:
            printf("OS/ABI: UNIX - System V\n");
            break;
        case ELFOSABI_HPUX:
            printf("OS/ABI: UNIX - HP-UX\n");
            break;
        case ELFOSABI_NETBSD:
            printf("OS/ABI: UNIX - NetBSD\n");
            break;
        case ELFOSABI_LINUX:
            printf("OS/ABI: UNIX - Linux\n");
            break;
        case ELFOSABI_IRIX:
            printf("OS/ABI: UNIX - IRIX\n");
            break;
        case ELFOSABI_SOLARIS:
            printf("OS/ABI: UNIX - Solaris\n");
            break;
        case ELFOSABI_AIX:
            printf("OS/ABI: UNIX - AIX\n");
            break;
        case ELFOSABI_FREEBSD:
            printf("OS/ABI: UNIX - FreeBSD\n");
            break;
        case ELFOSABI_TRU64:
            printf("OS/ABI: UNIX - TRU64\n");
            break;
        case ELFOSABI_MODESTO:
            printf("OS/ABI: Novell - Modesto\n");
            break;
        case ELFOSABI_OPENBSD:
            printf("OS/ABI: UNIX - OpenBSD\n");
            break;
        case ELFOSABI_ARM_AEABI:
            printf("OS/ABI: ARM EABI\n");
            break;
        case ELFOSABI_ARM:
            printf("OS/ABI: ARM\n");
            break;
        case ELFOSABI_STANDALONE:
            printf("OS/ABI: Standalone (embedded) application\n");
            break;
    }
    printf("ABI Version: %u\n", hdr.e_ident[EI_ABIVERSION]);

  //  printf("\nType: ");
    switch (hdr.e_type) {
        case ET_NONE:
            printf("Type: No file type\n");
            break;
        case ET_REL:
            printf("Type: Relocatable file\n");
            break;
        case ET_EXEC:
            printf("Type: Executable file\n");
            break;
        case ET_DYN:
            printf("Type: Shared object file\n");
            break;
        case ET_CORE:
            printf("Type: Core file\n");
            break;
        case ET_LOOS:
            printf("Type: Operating system-specific\n");
            break;
        case ET_HIOS:
            printf("Type: Operating system-specific\n");
            break;
        case ET_LOPROC:
            printf("Type: Processor-specific\n");
            break;
        case ET_HIPROC:
            printf("Type: Processor-specific\n");
            break;
        default:
            printf("Type: --\n");
    }


    switch (hdr.e_machine) {
        case EM_386:
            printf("Machine: Intel 80386\n");
            break;
        case EM_860:
            printf("Machine: Intel 80860\n");
            break;
        case EM_X86_64:
            printf("Machine: AMD x86-64 architecture\n");
            break;
    }
    printf("Version: 0x%d\n", hdr.e_version);

    // % вывести в нужной системе (dec, oct, hex ??)
    printf("Entry point address: %p\n", (void*)hdr.e_entry);
    printf("Start of program headers: %ld (bytes into file)\n", hdr.e_phoff);
    printf("Start of section headers: %ld (bytes into file)\n", hdr.e_shoff);
    printf("Flags: 0x%d\n", hdr.e_flags);
    printf("Size of this header:%d (bytes)\n", hdr.e_ehsize);
    printf("Size of program headers: %d (bytes)\n", hdr.e_phentsize);
    printf("Number of program headers: %d\n", hdr.e_phnum);
    printf("Size of section headers: %d (bytes)\n", hdr.e_shentsize);
    printf("Number of section headers: %d\n", hdr.e_shnum);
    printf("Section header string table index: %d\n", hdr.e_shstrndx);

    fclose(ElfFile);
    return 0;
}

