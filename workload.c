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

#define HUGEPAGE 2097152

#define str(s) #s
#define xstr(s) str(s)

#ifdef COMPLEX

#define GET_BIT(val, bit) (((val) >> (bit)) & 1)

uint64_t l2_set(uint64_t pa) {
    uint64_t set = 0;

    for (int i = 0; i < 11; i++) {
        uint64_t bit_val = 0;

        if (i >= 0 && i < 3) {
            bit_val = GET_BIT(pa, i + 6);
        } 
        else if (i >= 3 && i < 8) {
            bit_val = GET_BIT(pa, i + 6) ^ 
                      GET_BIT(pa, 31 - i) ^ 
                      GET_BIT(pa, i + 26);
        } 
        else if (i >= 8 && i < 11) {
            bit_val = GET_BIT(pa, i + 6) ^ 
                      GET_BIT(pa, 31 - i);
        }

        set |= (bit_val << i);
    }

    return set; //11 bit
}
#elif defined(LINEAR)
uint64_t l2_set(uint64_t pa) {
    return (pa >> 6) & 1023; //10 bits
}
#endif

uint64_t l1_set(uint64_t addr){
    return (addr >> 6) & 63; //6 bits
}

int main(){
    int fd = open("/proc/irqlog", O_RDONLY);

    uint64_t bases[WAYS];
    uint64_t attempt = 0;

    for(int i = 0; i < WAYS; i++){
    	bases[i] = (uint64_t)mmap((void *)(0x400000000 + (0x1000 * attempt)), 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

        //Demand paging
        *(volatile char *)bases[i] = 0x0;

        attempt++;

#if defined(LINEAR) || defined(COMPLEX)
        bases[i] += (l1_set(TARGET_PA) << 6);
#else
        bases[i] += ((rand() % 64) << 6);
#endif

        uint64_t bases_pa = bases[i];
        ioctl(fd, 1001, &bases_pa);

#ifdef LINEAR
        if(l2_set(bases_pa) != l2_set(TARGET_PA)){
            i--;
            continue;
        }
#elif defined(COMPLEX)
        if(l2_set(bases_pa) != l2_set(TARGET_PA)){
            i--;
            continue;
        }
#endif
    }

    while(1){
        asm(
            ".rept 100\n\t"
            ".set off, 0\n\t"
            ".rept " xstr(WAYS) "\n\t"
                "mov off(%[addrs_addr]), %%r8\n\t"
                "mov (%%r8), %%r8\n\t"
                ".set off, off + 8\n\t"
            ".endr\n\t"
            ".endr\n\t"
            :: [addrs_addr]"r"(bases) : "r8"
        );
    }
    
    return 0;
}
