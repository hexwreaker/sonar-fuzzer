
#include "sonar-debugger.h"
#include "sprf-parser.h"
#include "util.h"
#include <strings.h>

int debug_debugger = 2;

void getdata(pid_t child, long addr, long *dest) {   
    *dest = ptrace(PTRACE_PEEKDATA, child, addr, NULL);
    if (debug_debugger>=3) {printf("read  0x%016lx from 0x%016lx\n", *dest, addr);}
}

void putdata(pid_t child, long addr, long *value) {   
    ptrace(PTRACE_POKEDATA, child, addr, *value);
    if (debug_debugger>=3) {printf("write 0x%016lx   to 0x%016lx\n", *value, addr); }
}

int add_breakpoint(pid_t pid_target, struct sprf_file* sprfile, struct breakpoint *breakpoints, int breakpoint_address) {
    int num = breakpoint_address - sprfile->start_text_seg;
    breakpoints[num].address = breakpoint_address;

    // Read original instruction at the breakpoint address
    getdata(pid_target, breakpoint_address, &breakpoints[num].original_data);
    breakpoints[num].break_code = (breakpoints[num].original_data & (long)(0xffffffffffffff00)) + 0xcc;
    // Write breakpoint (0xCC is the x86 INT3 instruction)
    putdata(pid_target, breakpoint_address, &breakpoints[num].break_code);
    long val;
    getdata(pid_target, breakpoint_address, &val);

    if (debug_debugger>=2) { printf(BOLDGREEN"[i] add breakpoint %d at 0x%lx"BLACK GREEN"\n\t- original data : 0x%lx\n\t- break code : 0x%lx\n"BLACK, num, (long)breakpoints[num].address, breakpoints[num].original_data, breakpoints[num].break_code); }
    return 0;
}

int single_step(pid_t pid_target) {
    int status;
    // Perform single step
    if (ptrace(PTRACE_SINGLESTEP, pid_target, NULL, NULL) == -1) { printf(BOLDRED"[!] Error during PTRACE_SINGLESTEP"BLACK); return -1; }
    // Wait for the single step to complete
    if (waitpid(pid_target, &status, 0) == -1) { printf(BOLDRED"[!] Error waiting after PTRACE_SINGLESTEP"BLACK); return -1; }
    // Check if the child process is still running
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) { printf(BOLDRED"[!] Error: Tracee did not stop as expected after single step.\n"BLACK); return -1; }
    return 0;
}

// don"t forget to free(breakpoints returned)
struct breakpoint* set_breakpoints_from_probes(pid_t child, struct sprf_file* sprfile) {
    // Set all breakpoints in target
    struct breakpoint *breakpoints = (struct breakpoint*)malloc((sprfile->end_text_seg - sprfile->start_text_seg) * sizeof(struct breakpoint));
    bzero(breakpoints, (sprfile->end_text_seg - sprfile->start_text_seg) * sizeof(struct breakpoint));
    printf(BLACK "[i] allocating %ld breakpoints\n\t.text : 0x%lx-0x%lx\n" RESET, sprfile->probes_count, sprfile->start_text_seg, sprfile->end_text_seg);
    for (size_t i=0; i<sprfile->probes_count; i++) { add_breakpoint(child, sprfile, breakpoints, sprfile->probes[i]); }
    return breakpoints;
}
