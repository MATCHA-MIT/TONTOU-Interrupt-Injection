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

#define ROUNDS 10000

int main(int argc, char *argv[]) {
    uint64_t spinning = 0;
    if (argc > 1) {
        spinning = strtoull(argv[1], NULL, 10);
    }

    printf("%d\n", getpid());
    fflush(stdout);

    int fd = open("/proc/irqlog", O_RDONLY);

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

    for(int i = 0; i < ROUNDS; i++){
        int ret;
        uint64_t exp;

        asm volatile(
            "syscall"
            : "=a"(ret)
            : "a"(0),
            "D"(tfd),
            "S"(&exp),
            "d"(8)
            : "rcx","r11","r10","r8","r9","memory", "r12", "r13", "r14"
        );  
        
        for(volatile uint64_t b = 0; b < spinning; b++){}

        ioctl(fd, 0x1234, NULL);
    }

    // for(volatile uint64_t b = 0; b < 1000; b++){}
    
    return 0;
}
