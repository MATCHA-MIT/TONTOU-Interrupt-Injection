#!/usr/bin/env bash
set -e

SESSION=break_kaslr
CORES=8
tmux new-session -d -s "$SESSION" -n run

rm -f break_kaslr
rm -f workload

gcc -DSET=276 workload.c -o workload
gcc -pthread -no-pie -DCORES=$CORES break_kaslr.c -o break_kaslr

mkdir -p logs
for ((i=0; i < CORES; i++)); do
    fifo="logs/core$i"
    rm -f "$fifo"
    mkfifo "$fifo"
done

tmux send-keys -t "$SESSION:0.0" "{ time ./break_kaslr ; } 2>&1 | tee logs/kaslr.log &" C-m

for ((i=0; i < CORES; i++)); do
  if [ "$i" -ne 0 ]; then
    tmux split-window -t "$SESSION:0" -h
    tmux select-layout -t "$SESSION:0" tiled
  fi
  pane=$(tmux list-panes -t "$SESSION:0" -F '#P' | tail -n1)
  WORKLOAD_CORE=$((i + 8))
  tmux send-keys -t "$SESSION:0.$pane" "taskset -c $WORKLOAD_CORE ./workload &" C-m
  tmux send-keys -t "$SESSION:0.$pane" "cat <> logs/core$i" C-m
done

tmux attach -t "$SESSION" 2>/dev/null || true
tput cuu1; tput el     

tmux kill-session -t "$SESSION" 2>/dev/null || true
cat logs/kaslr.log
