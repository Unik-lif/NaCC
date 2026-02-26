#!/bin/bash

# Ensure we are in tmux
if [ -z "$TMUX" ]; then
    echo "Error: You must be running inside tmux to use this feature."
    exit 1
fi

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
tmux send-keys -t "$LEFT_PANE" "make vm" C-m

# 5. Setup Top-Right: make gdb (Debugger)
tmux send-keys -t "$RIGHT_PANE" "make gdb" C-m
# "Wheelchair" mode: Auto-send 'c' to start execution after a short delay
# Requires running in background so we can proceed to launch qemu
(sleep 2; tmux send-keys -t "$RIGHT_PANE" "c" C-m) &

# 6. Setup Bottom: make launch (QEMU)
# Switch focus back to bottom pane, then exec into it
tmux select-pane -t "$BOTTOM_PANE"
echo "Starting QEMU in bottom pane..."
clear
exec make launch DEBUG=1

