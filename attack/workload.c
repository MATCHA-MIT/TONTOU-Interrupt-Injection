#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <time.h>
#include <sched.h>
#include <errno.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <signal.h>
#include <setjmp.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdlib.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <time.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>

#define WAYS 16
#define SETS 1024
#define HUGEPAGE 2097152

#define str(s) #s
#define xstr(s) str(s)

void get_addrs(uint64_t base, uint64_t *buf, uint64_t set, int amount){
    for(int i = 0; i < amount; i++){
        buf[i] = ((((((uint64_t)base) >> 16) + i) << 10) + set) << 6;
    }
}

int main(){
    volatile char *base = aligned_alloc(HUGEPAGE, HUGEPAGE);
    madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);
    mprotect((void *)base, HUGEPAGE, PROT_READ|PROT_WRITE|PROT_EXEC);

    uint64_t addrs[SETS * WAYS];
    for(int i = 0; i < SETS; i++){
        get_addrs((uint64_t)base, addrs + (WAYS * i), i, WAYS);
    }

    while(1){
        asm(
            "movq %[addrs_addr], %%r9\n\t"
            ".rept 100\n\t"
            "mov "xstr(((SET * WAYS + 0) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 1) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 2) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 3) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 4) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 5) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 6) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 7) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 8) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 9) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 10) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 11) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
            "mov "xstr(((SET * WAYS + 12) * 8)) "(%[addrs_addr]), %%r8\n\t"
            "mov (%%r8), %%r8\n\t"
        ".endr\n\t"
            :: [addrs_addr]"r"(addrs): "r8"
        );
    }

    return 0;
}
