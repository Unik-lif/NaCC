#!/bin/bash

# Ensure we are in tmux
if [ -z "$TMUX" ]; then
    echo "Error: You must be running inside tmux to use this feature."
    exit 1
fi

# 1. Split the window to create the layout
# Current pane (Bottom) will run 'make launch'
# We create a top pane first (-v -b means vertical, before/above)
TOP_PANE=$(tmux split-window -v -b -P -F "#{pane_id}" -c "#{pane_current_path}")

# 2. Split the top pane into Top-Left and Top-Right
# -h means horizontal
RIGHT_PANE=$(tmux split-window -h -P -F "#{pane_id}" -t "$TOP_PANE" -c "#{pane_current_path}")
LEFT_PANE="$TOP_PANE"

# 3. Setup Top-Left: make vm (Connect to VM)
tmux send-keys -t "$LEFT_PANE" "make vm" C-m # Using vm2 to avoid recursive make issues if any, or just vm

# 4. Setup Top-Right: make gdb (Debugger)
tmux send-keys -t "$RIGHT_PANE" "make gdb" C-m
# "Wheelchair" mode: Auto-send 'c' to start execution after a short delay
# Requires running in background so we can proceed to launch qemu
(sleep 2; tmux send-keys -t "$RIGHT_PANE" "c" C-m) &

# 5. Setup Bottom (Current): make launch (QEMU)
# We exec into it to replace the current process
echo "Starting QEMU in bottom pane..."
# Clear screen for cleaner look
clear
exec make launch DEBUG=1
