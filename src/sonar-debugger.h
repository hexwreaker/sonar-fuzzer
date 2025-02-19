#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "sprf-parser.h"

// Structure to represent a breakpoint
struct breakpoint {
    uint64_t address;
    long original_data;
    long break_code;
};

// Function declarations
void getdata(pid_t child, long addr, long *dest);
void putdata(pid_t child, long addr, long *value);
int add_breakpoint(pid_t pid_target, struct sprf_file* sprfile, struct breakpoint *breakpoints, int breakpoint_address);
int single_step(pid_t pid_target);
struct breakpoint* set_breakpoints_from_probes(pid_t child, struct sprf_file* sprfile);

#endif // DEBUGGER_H
