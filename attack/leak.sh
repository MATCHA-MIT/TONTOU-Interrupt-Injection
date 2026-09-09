#!/usr/bin/env bash
set -e

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 _text physmap target"
    exit 1
fi

SESSION=leak_data
CORES=8
tmux new-session -d -s "$SESSION" -n run

rm -f leak_data
rm -f workload

gcc -DSET=276 workload.c -o workload
gcc -pthread -no-pie -DCORES=$CORES leak_data.c -o leak_data

mkdir -p logs
for ((i=0; i < CORES; i++)); do
    fifo="logs/core$i"
    rm -f "$fifo"
    mkfifo "$fifo"
done

tmux send-keys -t "$SESSION:0.0" "time ./leak_data "$1" "$2" "$3" &" C-m

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

tmux attach -t "$SESSION"

watch -t -n 0.2 'cat live_leak.txt'
