#!/bin/bash
tmux has-session -t ioring_demo 2>/dev/null
if [ $? == 0 ]; then
    tmux kill-session -t ioring_demo
fi
tmux new-session -d -s ioring_demo
tmux set-option -t ioring_demo -g mouse on
tmux split-window -v -p 35
tmux split-window -h -p 50
tmux send-keys -t ioring_demo:0.0 "sudo ./run.sh" C-m
tmux send-keys -t ioring_demo:0.1 "clear" C-m
tmux send-keys -t ioring_demo:0.1 "sudo ./test-programs/simulator/stress_test"
tmux send-keys -t ioring_demo:0.2 "mkdir -p /tmp/ioring_vault" C-m
tmux send-keys -t ioring_demo:0.2 "watch -n 0.5 -t 'echo \"RANSOMWARE AUTO-ROLLBACK VAULT\"; echo \"--------------------------------\"; ls -lh /tmp/ioring_vault/'" C-m
tmux select-pane -t ioring_demo:0.1
tmux attach-session -t ioring_demo
