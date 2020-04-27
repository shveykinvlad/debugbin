/* Copyright 2017 Shveykin Vladislav */

#include <stdint.h>
#include <sys/types.h>

struct breakpoint;

typedef struct breakpoint breakpoint;

void procmsg(const char* format, ...);

void dbg_run_target(const char* programname);

uint64_t dbg_get_child_pc(pid_t pid);

void* dbg_get_child_ip(pid_t pid);

uint64_t dbg_get_reg(pid_t pid, char* reg);

long dbg_get_data(pid_t pid, void* addr);

void* dbg_get_breakpoint_addr(breakpoint *bp);

void dbg_enable_breakpoint(pid_t pid, breakpoint *bp);

void dbg_disable_reakpoint(pid_t pid, breakpoint *bp);

breakpoint* dbg_add_breakpoint(breakpoint *head, pid_t pid, void* addr);

breakpoint* dbg_delete_breakpoint(breakpoint *head, pid_t pid, void* addr);

breakpoint* dbg_clean_breakpoint(breakpoint *head);

breakpoint* dbg_get_breakpoint(breakpoint* head, void* addr);

void dbg_print_breakpoints(breakpoint* head);

breakpoint *dbg_create_breakpoint(pid_t pid, void* addr);

int dbg_run(pid_t pid, int cmd);

int dbg_resume_from_breakpoint(pid_t pid, breakpoint *bp);

size_t get_tids(pid_t **const listptr, size_t *const sizeptr, const pid_t pid);

int dbg_get_elf_header(const char* programname);


