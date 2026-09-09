
#!/bin/bash

if [[ "$*" == *"-zen2"* ]]; then
    PLATFORM_FLAGS="-DAMD -DZEN2"
    L2_HASH_FUNCTION="-DLINEAR"
    PL2_WAYS=13
    BEST_I=1
    BEST_S=6181
    BEST_S_NOISE=2101
    BEST_S_TARGETED=1001
    SIBLING_CORE=10
elif [[ "$*" == *"-zen4"* ]]; then
    PLATFORM_FLAGS="-DAMD -DZEN4"
    L2_HASH_FUNCTION="-DCOMPLEX"
    PL2_WAYS=13
    BEST_I=1
    BEST_S=3911
    BEST_S_NOISE=2650
    BEST_S_TARGETED=2011
    SIBLING_CORE=34
elif [[ "$*" == *"-cascade"* ]]; then
    PLATFORM_FLAGS="-DAMD -DCASCADE"
    L2_HASH_FUNCTION="-DLINEAR"
    PL2_WAYS=17
    BEST_I=1
    BEST_S=1
    SIBLING_CORE=49
elif [[ "$*" == *"-arrow"* ]]; then
    PLATFORM_FLAGS="-DAMD -DARROW"
    L2_HASH_FUNCTION="-DLINEAR"
    PL2_WAYS=17
    BEST_I=1
    BEST_S=1
    SIBLING_CORE=0
else
    echo "Pick -zen2, -zen4, -cascade or -arrow"
    exit
fi

pkill workload

gcc attacker_ab.c -o attacker_ab -DINTERVAL=$BEST_I

echo "WITHOUT NOISE"

sudo rmmod kprobe_logger >/dev/null 2>&1
make clean >/dev/null 2>&1

 for V in 0 7 15 23 31 39 47 55 63; do
    counts=()
    make CFLAGS_MODULE="-DPRECISE -DVICTIM_NOPS=$V $PLATFORM_FLAGS" >/dev/null 2>&1
    for rep in $(seq 1 10); do
        sudo insmod kprobe_logger.ko

        TMP=/tmp/prog.out

        PID=$(
        { taskset -c 2 ./attacker_ab $BEST_S | tee "$TMP" & } | {
            IFS= read -r FIRST
            echo "$FIRST"
            cat >/dev/null
        }
        )

        sudo rmmod kprobe_logger

        c=$(sudo dmesg | grep 'counter_victim' | tail -n1 | awk '{print $NF}')
        counts+=("$c")
    done

    sorted=($(printf "%s\n" "${counts[@]}" | sort -n))
    med=$(( (sorted[4] + sorted[5]) / 2 ))

    printf "NOP = %2d  ->  %d\n" "$V" "$med"
done

if [[ "$*" != *"-arrow"* ]]; then
    echo "WITH UNRELATED NOISE"

    sudo rmmod kprobe_logger >/dev/null 2>&1
    make clean >/dev/null 2>&1

    for V in 0 7 15 23 31 39 47 55 63; do
        counts=()
        make CFLAGS_MODULE="-DPRECISE -DVICTIM_NOPS=$V $PLATFORM_FLAGS" >/dev/null 2>&1
        for rep in $(seq 1 10); do
            sudo insmod kprobe_logger.ko

            PA=$(sudo dmesg | grep "victim_start:" | tail -n 1 | sed -n 's/.*PA: \([0-9a-fA-F]*\).*/\1/p')

            TMP=/tmp/prog.out

            gcc workload.c -o workload -DWAYS=$PL2_WAYS >/dev/null 2>&1

            taskset -c $SIBLING_CORE ./workload &
            WORKLOAD_PID=$!

            sleep 1;

            PID=$(
            { taskset -c 2 ./attacker_ab $BEST_S_NOISE | tee "$TMP" & } | {
                IFS= read -r FIRST
                echo "$FIRST"
                cat >/dev/null
            }
            )

            sudo rmmod kprobe_logger

            c=$(sudo dmesg | grep 'counter_victim' | tail -n1 | awk '{print $NF}')
            counts+=("$c")

            kill $WORKLOAD_PID
            wait $WORKLOAD_PID 2>/dev/null
        done

        sorted=($(printf "%s\n" "${counts[@]}" | sort -n))
        med=$(( (sorted[4] + sorted[5]) / 2 ))

        printf "NOP = %2d  ->  %d\n" "$V" "$med"
    done

    echo "WITH TARGETED NOISE"

    sudo rmmod kprobe_logger >/dev/null 2>&1
    make clean >/dev/null 2>&1

    for V in 0 7 15 23 31 39 47 55 63; do
        counts=()
        make CFLAGS_MODULE="-DPRECISE -DVICTIM_NOPS=$V $PLATFORM_FLAGS" >/dev/null 2>&1
        for rep in $(seq 1 10); do
            sudo insmod kprobe_logger.ko >/dev/null 2>&1

            PA=$(sudo dmesg | grep "victim_start:" | tail -n 1 | sed -n 's/.*PA: \([0-9a-fA-F]*\).*/\1/p')

            TMP=/tmp/prog.out

            gcc workload.c -o workload -DTARGET_PA=0x$PA $L2_HASH_FUNCTION -DWAYS=$PL2_WAYS >/dev/null 2>&1

            taskset -c $SIBLING_CORE ./workload &
            WORKLOAD_PID=$!

            sleep 5;

            PID=$(
            { taskset -c 2 ./attacker_ab $BEST_S_TARGETED | tee "$TMP" & } | {
                IFS= read -r FIRST
                echo "$FIRST"
                cat >/dev/null
            }
            )

            sudo rmmod kprobe_logger

            c=$(sudo dmesg | grep 'counter_victim' | tail -n1 | awk '{print $NF}')
            counts+=("$c")

            kill $WORKLOAD_PID
            wait $WORKLOAD_PID 2>/dev/null
        done

        sorted=($(printf "%s\n" "${counts[@]}" | sort -n))
        med=$(( (sorted[4] + sorted[5]) / 2 ))

        printf "NOP = %2d  ->  %d\n" "$V" "$med"
    done
fi
