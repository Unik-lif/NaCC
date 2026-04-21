#!/bin/bash

AUTO_CMD="${VM_AUTO_CMD:-${1:-}}"
GDB_PROMPT_TIMEOUT_SECONDS=30

send_gdb_continue_when_ready() {
    local gdb_pane=$1
    local deadline=$((SECONDS + GDB_PROMPT_TIMEOUT_SECONDS))

    while [ "$SECONDS" -lt "$deadline" ]; do
        if tmux capture-pane -pt "$gdb_pane" -S - 2>/dev/null | grep -Fq "(gdb)"; then
            tmux send-keys -t "$gdb_pane" "c" C-m
            return 0
        fi
        sleep 1
    done

    tmux send-keys -t "$gdb_pane" "c" C-m
}

# Ensure we are in tmux
if [ -z "$TMUX" ]; then
    echo "Error: You must be running inside tmux to use this feature."
    exit 1
fi

# Increase history limit for the current session
tmux set-option -g history-limit 100000

# Record the current (bottom) pane id BEFORE any splits (splits move focus)
BOTTOM_PANE=$(tmux display-message -p "#{pane_id}")

# 1. Split the window to create the layout
# Current pane (Bottom) will run 'make launch'
# We create a top pane first (-v -b means vertical, before/above)
TOP_PANE=$(tmux split-window -v -b -P -F "#{pane_id}" -c "#{pane_current_path}")

# 2. Split the top pane into Top-Left and Top-Right
# -h means horizontal
RIGHT_PANE=$(tmux split-window -h -P -F "#{pane_id}" -t "$TOP_PANE" -c "#{pane_current_path}")
LEFT_PANE="$TOP_PANE"

# 3. Assign titles to each pane for reliable identification
tmux select-pane -t "$BOTTOM_PANE" -T "nacc-qemu"
tmux select-pane -t "$LEFT_PANE"   -T "nacc-vm"
tmux select-pane -t "$RIGHT_PANE"  -T "nacc-gdb"

# 4. Setup Top-Left: make vm (Connect to VM)
VM_CMD="make vm"
if [ -n "$AUTO_CMD" ]; then
    printf -v AUTO_CMD_Q "%q" "$AUTO_CMD"
    VM_CMD+=" VM_AUTO_CMD=$AUTO_CMD_Q"
fi
tmux send-keys -t "$LEFT_PANE" "$VM_CMD" C-m

# 5. Setup Top-Right: make gdb (Debugger)
tmux send-keys -t "$RIGHT_PANE" "make gdb" C-m
# Auto-continue only after GDB reaches its prompt; a fixed sleep races detached runs.
(send_gdb_continue_when_ready "$RIGHT_PANE") &

# 6. Setup Bottom: make launch (QEMU)
# Switch focus back to bottom pane, then exec into it
tmux select-pane -t "$BOTTOM_PANE"
echo "Starting QEMU in bottom pane..."
clear
exec make launch DEBUG=1
