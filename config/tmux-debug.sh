#!/bin/bash

AUTO_CMD="${VM_AUTO_CMD:-${1:-}}"
GDB_PROMPT_TIMEOUT_SECONDS=30
GDB_CONTINUE_OBSERVE_TIMEOUT_SECONDS=10
GDB_PAGER_PROMPT="--Type <RET> for more, q to quit, c to continue without paging--"
GDB_PAGER_PROMPT_COMPACT="${GDB_PAGER_PROMPT//[[:space:]]/}"
GDB_AUTO_CONTINUE_MARKER="[NaCC][gdb-auto-continue]"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DISK_PATH="$REPO_ROOT/NaCC.qcow2"
DISK_NAME="$(basename "$DISK_PATH")"
DISK_DIR="$(dirname "$DISK_PATH")"
QEMU_SYSTEM_NAME="qemu-system-riscv64"

find_live_qemu_owner() {
    local proc_dir pid exe_target exe_name cmdline cwd

    for proc_dir in /proc/[0-9]*; do
        pid="${proc_dir##*/}"
        exe_target=$(readlink "$proc_dir/exe" 2>/dev/null) || continue
        exe_target="${exe_target% (deleted)}"
        exe_name="${exe_target##*/}"
        [ "$exe_name" = "$QEMU_SYSTEM_NAME" ] || continue

        cmdline=$(tr '\0' ' ' < "$proc_dir/cmdline" 2>/dev/null) || continue
        [ -n "$cmdline" ] || continue

        if [[ "$cmdline" == *"$DISK_PATH"* ]]; then
            printf '%s\t%s\n' "$pid" "$cmdline"
            return 0
        fi

        [[ "$cmdline" == *"$DISK_NAME"* ]] || continue

        cwd=$(readlink -f "$proc_dir/cwd" 2>/dev/null) || continue
        if [ "$cwd" = "$REPO_ROOT" ] || [ "$cwd" = "$DISK_DIR" ]; then
            printf '%s\t%s\n' "$pid" "$cmdline"
            return 0
        fi
    done

    return 1
}

capture_pane_screen() {
    tmux capture-pane -J -pt "$1" 2>/dev/null || true
}

wait_for_gdb_marker_and_prompt() {
    local gdb_pane=$1
    local marker=$2
    local timeout_seconds=$3
    local deadline=$((SECONDS + timeout_seconds))
    local pane_text

    while [ "$SECONDS" -lt "$deadline" ]; do
        pane_text=$(capture_pane_screen "$gdb_pane")
        if [[ "$pane_text" == *"$marker"* && "$pane_text" == *"(gdb)"* ]]; then
            return 0
        fi
        sleep 1
    done

    return 1
}

wait_for_gdb_continue_observed() {
    local gdb_pane=$1
    local deadline=$((SECONDS + GDB_CONTINUE_OBSERVE_TIMEOUT_SECONDS))
    local pane_text

    while [ "$SECONDS" -lt "$deadline" ]; do
        pane_text=$(capture_pane_screen "$gdb_pane")
        if [[ "$pane_text" == *"Continuing."* ]]; then
            printf '[NaCC][gdb-continue-observed] pane=%s\n' "$gdb_pane"
            return 0
        fi
        sleep 1
    done

    return 1
}

attempt_gdb_continue() {
    local gdb_pane=$1

    tmux send-keys -t "$gdb_pane" "echo $GDB_AUTO_CONTINUE_MARKER\\n" C-m
    if ! wait_for_gdb_marker_and_prompt "$gdb_pane" "$GDB_AUTO_CONTINUE_MARKER" 5; then
        printf '[NaCC][gdb-auto-continue] pane=%s marker_not_observed_before_continue\n' "$gdb_pane"
    fi

    tmux send-keys -t "$gdb_pane" "c" C-m
    if ! wait_for_gdb_continue_observed "$gdb_pane"; then
        printf '[NaCC][gdb-continue-unconfirmed] pane=%s\n' "$gdb_pane"
    fi
}

send_gdb_continue_when_ready() {
    local gdb_pane=$1
    local deadline=$((SECONDS + GDB_PROMPT_TIMEOUT_SECONDS))
    local pane_text
    local compact_pane_text

    while [ "$SECONDS" -lt "$deadline" ]; do
        # Only inspect the current screen; full history keeps stale pager prompts after GDB resumes.
        pane_text=$(capture_pane_screen "$gdb_pane")
        compact_pane_text="${pane_text//[[:space:]]/}"

        if [[ "$pane_text" == *"(gdb)"* ]]; then
            attempt_gdb_continue "$gdb_pane"
            return 0
        fi
        if [[ "$compact_pane_text" == *"$GDB_PAGER_PROMPT_COMPACT"* ]]; then
            tmux send-keys -t "$gdb_pane" "c"
            sleep 1
            continue
        fi
        sleep 1
    done

    printf '[NaCC][gdb-ready-timeout] pane=%s\n' "$gdb_pane"
    attempt_gdb_continue "$gdb_pane"
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
tmux select-pane -t "$BOTTOM_PANE" -T "nacc-qemu"
tmux set-option -pt "$BOTTOM_PANE" remain-on-exit on >/dev/null 2>&1 || true

if OWNER_INFO=$(find_live_qemu_owner); then
    OWNER_PID=${OWNER_INFO%%$'\t'*}
    OWNER_ARGS=${OWNER_INFO#*$'\t'}
    printf '[NaCC][qemu-owner-block] %s is already in use by qemu pid %s\n' "$DISK_PATH" "$OWNER_PID"
    printf '[NaCC][qemu-owner-block] command: %s\n' "$OWNER_ARGS"
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

# 3. Assign titles to each pane for reliable identification
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
