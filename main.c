/* Copyright 2017 Shveykin Vladislav */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>

#include "debuglib_64.h"

breakpoint *bp;
breakpoint *current_bp;
static pid_t child_pid;
static bool is_running;
static bool is_breakpoint;

pid_t *tid = 0;
size_t tids = 0;
size_t tids_max = 0;
size_t t, s;

static size_t split(char *buffer, char *args[], size_t args_size) {
    char *p, *start_of_word = NULL;

    size_t arg_count = 0;
    bool in_word = false;
    for (p = buffer; arg_count < args_size && *p != '\0'; p++) {
        char c = *p;
        if (!in_word) {
            if (!isspace(c)) {
                in_word = true;
                start_of_word = p;
            }
        } else if (in_word) {
            if (isspace(c)) {
                *p = 0;
                args[arg_count++] = start_of_word;
                in_word = false;
            }
        }
    }
    if (in_word == true && arg_count < args_size)
        args[arg_count++] = start_of_word;

    return arg_count;
}

static char* to_lower_case(char *string) {
    for (int i = 0; i < strlen(string); i++) {
        string[i] = tolower(string[i]);
    }
    return string;
}

static void command_line(const char* programname) {
    char line[255];
    char *args[20];
    char *command;
    size_t arg_count;

    int status;
    printf("(debug) ");

    if (fgets(line, 255, stdin) == 0) {
        perror("fgets");
    }
    to_lower_case(line);
    arg_count = split(line, args, 20);

    command = args[0];

    if (strcmp(command, "run") == 0) {
        if (!is_running) {
            child_pid = fork();

            if (child_pid == 0) {
                dbg_run_target(programname);

            } else if (child_pid > 0) {
                is_running = true;
                is_breakpoint = false;
                procmsg("Debugger started\n");
                wait(0);
                procmsg("Child now at RIP = 0x%08x\n", dbg_get_child_pc(child_pid));
                tids = get_tids(&tid, &tids_max, child_pid);
                printf("Process %d has %d tasks,\n", (int)child_pid, (int)tids);

            } else {
                perror("fork");
                // return -1;
            }

        } else {
            printf("The program being debugged has been started already.\n");
        }

    } else if (strcmp(command, "s") == 0) {
        if (!is_breakpoint) {
            status = (dbg_run(child_pid, PTRACE_SINGLESTEP));

            if (status == 1) {
                procmsg("now RIP = 0x%08X\n", dbg_get_child_pc(child_pid));
                if (dbg_get_breakpoint(bp, (void*)(dbg_get_child_pc(child_pid)-1)) != NULL) {
                    is_breakpoint = true;
                    procmsg("Child stopped at breakpoint. RIP = 0x%08X\n",
                            dbg_get_child_pc(child_pid)-1);
                }

            } else if (status == 0) {
                bp = dbg_clean_breakpoint(bp);
                is_breakpoint = false;
                is_running = false;
                procmsg("Child exited\n");

            } else {
                procmsg("Unexpected error: %d\n", status);
            }

        } else {
            procmsg("Child stopped at breakpoint. RIP = 0x%08X\n",
                    dbg_get_child_pc(child_pid)-1);
        }

    } else if (strcmp(command, "c") == 0) {
        if (!is_breakpoint) {
            status = (dbg_run(child_pid, PTRACE_CONT));

            if (status == 1) {
                is_breakpoint = true;
                procmsg("Child stopped at breakpoint. RIP = 0x%08X\n",
                        dbg_get_child_pc(child_pid) - 1);

            } else if (status == 0) {
                bp = dbg_clean_breakpoint(bp);
                is_breakpoint = false;
                is_running = false;
                procmsg("Child exited\n");

            } else {
                procmsg("Unexpected error: %d\n", status);
            }

        } else {
            procmsg("Child stopped at breakpoint. RIP = 0x%08X\n",
                    dbg_get_child_pc(child_pid)-1);
        }

    } else if (strcmp(command, "resume") == 0) {
        if (is_breakpoint) {
            void* current_addr = (void*)(dbg_get_child_pc(child_pid) - 1);
            current_bp = dbg_get_breakpoint(bp, current_addr);
            status = dbg_resume_from_breakpoint(child_pid, current_bp);

            if (status == 0) {
                bp = dbg_clean_breakpoint(bp);
                is_breakpoint = false;
                is_running = false;
                procmsg("Child exited\n");

            } else if (status == 1) {
                procmsg("Child resumed\n");
                is_breakpoint = false;

            } else {
                procmsg("Unexpected error: %d\n", status);
            }
        } else {
        procmsg("Child not stopped at breakpoint");
        }

    } else if (strcmp(command, "break") == 0) {
        long int bp_addr = strtol(args[1], NULL, 16);
        bp = dbg_add_breakpoint(bp, child_pid, (void*)bp_addr);
        procmsg("Breakpoint created at %p\n",
                (void*)dbg_get_breakpoint_addr(bp));

    } else if (strcmp(command, "dbreak") == 0) {
        long int bp_addr = strtol(args[1], NULL, 16);
        bp = dbg_delete_breakpoint(bp, child_pid, (void*)bp_addr);
        procmsg("Breakpoint deleted from %p\n", (void*)bp_addr);


    } else if (strcmp(command, "info") == 0) {
        tids = get_tids(&tid, &tids_max, child_pid);
        printf("Process %d has %d tasks,\n", (int)child_pid, (int)tids);

        if (strcmp(args[1], "registers") == 0) {
            printf("%s: 0x%016lx\n", args[2], dbg_get_reg(child_pid, args[2]));

        } else if (strcmp(args[1], "elf") == 0) {
            dbg_get_elf_header(programname);

        } else if (strcmp(args[1], "data") == 0) {
            long int data_addr = strtol(args[2], NULL, 16);
            printf("data: %ld\n", dbg_get_data(child_pid, (void*) data_addr));

        } else if (strcmp(args[1], "breakpoints") == 0) {
            dbg_print_breakpoints(bp);

        } else {
            printf("Undefined command: \"%s %s\". Try \"help\"\n", command , args[1]);
        }

    } else if (strcmp(command, "quit") == 0 || (strcmp(command, "q")) == 0) {
        if (child_pid > 0) {
        kill(child_pid, SIGTERM);
        }
        exit(EXIT_SUCCESS);

    } else if (strcmp(command, "help") == 0) {
        printf("\"run\" - Start debugging\n");
        printf("\"break <address>\" - Add breakpoint");
        printf("\"s\" - Restart the stopped tracee process and stop at the next entry to or exit from system call\n");
        printf("\"c\" - Restart the stopped tracee process\n");
        printf("\"q\" - Quit\n");
        printf("\"info elf\" - Print ELF header\n");
        printf("\"info data <address>\" - Print data\n");
        printf("\"info registers <register>\" - Print register\n");
        printf("\"info breakpoints\" - Print breakpoints\n");

    } else {
        printf("Undefined command: \"%s\". Try \"help\"\n", command);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Expected a program name as argument\n");
        return -1;
    }
    while (true)
        command_line(argv[1]);
    return 0;
}
