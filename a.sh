#!/bin/bash

if [[ "$*" == *"-zen2"* ]]; then
    PLATFORM_FLAGS="-DAMD -DZEN2"
elif [[ "$*" == *"-zen4"* ]]; then
    PLATFORM_FLAGS="-DAMD -DZEN4"
elif [[ "$*" == *"-cascade"* ]]; then
    PLATFORM_FLAGS="-DAMD -DCASCADE"
elif [[ "$*" == *"-arrow"* ]]; then
    PLATFORM_FLAGS="-DAMD -DARROW"
else
    echo "Pick -zen2, -zen4, -cascade or -arrow"
    exit
fi

sudo rmmod kprobe_logger >/dev/null 2>&1
make CFLAGS_MODULE="-DVICTIM_NOPS=0 $PLATFORM_FLAGS" >/dev/null 2>&1

pkill workload
sudo rmmod kprobe_logger >/dev/null 2>&1

for I in $(seq 1 250 20000); do
    for S in $(seq 1 250 20000); do
        gcc attacker_ab.c -o attacker_ab -DINTERVAL=$I
    
        counts=()
        for rep in $(seq 1 10); do
            sudo insmod kprobe_logger.ko

            TMP=/tmp/prog.out

            PID=$(
            { taskset -c 0 ./attacker_ab $S | tee "$TMP" & } | {
                IFS= read -r FIRST
                echo "$FIRST"
                cat >/dev/null
            }
            )
            
            sudo rmmod kprobe_logger

            c=$(sudo dmesg | grep 'counter_syscall' | tail -n1 | awk '{print $NF}')
            counts+=("$c")
        done

        sorted=($(printf "%s\n" "${counts[@]}" | sort -n))
        med=$(( (sorted[4] + sorted[5]) / 2 ))

        printf "INTERVAL = %6d, SPINNING = %6d  ->  %d (min %d, max %d)\n" "$I" "$S" "$med" "${sorted[0]}" "${sorted[9]}"
    done
done
