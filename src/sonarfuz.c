#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "sprf-parser.h"
#include "sonar-debugger.h"
#include "util.h"

char debug = 0;

int hook() {
    // DO WHAT YOU WANT IN THIS FUNCTION !
    // this func is call when a breakpoint is hit.
    return 0;
}

int exec_target(struct sprf_file* sprfile, char *target) {

    pid_t child = fork();
    if (child == 0) {
        // Tracee: Request tracing
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(target, target, NULL);
    } else {
        int status;
        struct user_regs_struct regs;
        // Wait for the child to stop
        waitpid(child, &status, 0);
        // Le fils a t-il terminé ?
        if (!WIFSTOPPED(status)) { printf(BOLDMAGENTA"Unexpected stop status: %d\n"BLACK, status); return -1; }
        
        struct breakpoint* breakpoints = set_breakpoints_from_probes(child, sprfile);

        // run
        while (1) {
            // Continue
            if (ptrace(PTRACE_CONT, child, NULL, NULL) == -1) { printf(BOLDRED"[!] error : ptrace CONT\n"BLACK); return -1; }
            // Wait child to stop
            waitpid(child, &status, 0); // Wait for the child to hit the breakpoint
            // Breakpoint hit !
            if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
                // Get registers
                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                int num = (int)regs.rip-1 - sprfile->start_text_seg;
                if (debug>=1) {printf(BLUE"-> Breakpoint %d at 0x%lx hit !\n"BLACK, num, (long)regs.rip-1);}
                // printf("original data : 0x%016lx\n", breakpoints[num].original_data);

                // Set RIP to breakpoint address
                regs.rip = breakpoints[num].address;
                if (ptrace(PTRACE_SETREGS, child, NULL, &regs) == -1) { printf(BOLDRED"[!] Error setting registers (PTRACE_SETREGS)"BLACK); return -1; }

                // Restore original instruction at the breakpoint
                putdata(child, breakpoints[num].address, &breakpoints[num].original_data);

                // Call the hook function
                hook();

                // Perform single step
                single_step(child);
                // single_step(child);

                ptrace(PTRACE_GETREGS, child, NULL, &regs);
                // printf(BLUE"þ Breakpoint %d at 0x%lx hit !\n"BLACK, num, regs.rip);
                // Reset the 0xcc breakpoint instruction
                putdata(child, breakpoints[num].address, &breakpoints[num].break_code);
                // long val;
                // getdata(child, regs.rip, &val);
            }
            else {
                printf(BLACK"[!] END : Program terminated.\n"BLACK);
                free(breakpoints);
                return 1;
            }
        }
        free(breakpoints);
        printf("Child process exited.\n");
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <target.prf> <target>\n", argv[0]);
        return 1;
    }
    printf(BLACK"Start fuzzer...\n\ttarget : %s\n\tprofile : %s\n", argv[2], argv[1]);
    debug = 1;
    struct sprf_file* sprfile = load_sprf_file(argv[1]);
    if (sprfile == NULL) { printf(BOLDRED"[!] error : impossible de récupérer les informations depuis le fichier de profil \"%s\"\n"BLACK, argv[1]); return -1; }

    printf("start fuzzing...\n");
    // start FUZZING
    exec_target(sprfile, argv[2]);

    free(sprfile);
    return 0;
}