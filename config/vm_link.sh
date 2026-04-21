#!/bin/bash

LOG_DIR="logs"
SSH_READY_TIMEOUT_SECONDS="${VM_SSH_READY_TIMEOUT_SECONDS:-60}"
SSH_READY_PROBE_TIMEOUT_SECONDS=10
SSH_AUTO_TIMEOUT_SECONDS="${VM_SSH_AUTO_TIMEOUT_SECONDS:-120}"
SSH_BASE_CMD=(ssh -p 2222 root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
HAS_SSHPASS=0

if command -v sshpass &> /dev/null; then
    HAS_SSHPASS=1
fi

run_ssh() {
    if [ "$HAS_SSHPASS" -eq 1 ]; then
        sshpass -p riscv "$@"
    else
        "$@"
    fi
}

run_ssh_with_timeout() {
    local timeout_seconds=$1
    shift

    if [ "$HAS_SSHPASS" -eq 1 ]; then
        timeout --foreground "$timeout_seconds" sshpass -p riscv "$@"
    else
        "$@"
    fi
}

wait_for_authenticated_ssh() {
    if [ "$HAS_SSHPASS" -ne 1 ]; then
        echo "[NaCC][ssh-ready] skipping authenticated probe because sshpass is unavailable"
        return 0
    fi

    local deadline=$((SECONDS + SSH_READY_TIMEOUT_SECONDS))
    local attempts=0
    local last_exit=0

    echo "Waiting for authenticated SSH readiness..."
    while true; do
        attempts=$((attempts + 1))
        timeout --foreground "$SSH_READY_PROBE_TIMEOUT_SECONDS" \
            sshpass -p riscv "${SSH_BASE_CMD[@]}" true >/dev/null 2>&1
        last_exit=$?
        if [ "$last_exit" -eq 0 ]; then
            echo "[NaCC][ssh-ready] authenticated after $attempts attempt(s)"
            return 0
        fi
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "[NaCC][ssh-ready-timeout] no authenticated SSH session after ${SSH_READY_TIMEOUT_SECONDS}s (last_exit=$last_exit)"
            return 1
        fi
        sleep 1
    done
}

# Setup cleanup trap for the logger
cleanup() {
    if [ -n "$LOGGER_PID" ]; then
        kill "$LOGGER_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# Optional: Command to run automatically upon login
# You can set this via argument: ./vm_link.sh "command"
# Or uncomment below to set a default:
# AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox echo test"
# AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox echo test"
# AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox sh -c \"echo hello > /tmp/test.txt && cat /tmp/test.txt\""
# AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox sh -c 'echo hello; echo b; echo c'"
# AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox sh -c \"cat /tmp/test.txt\""
DEFAULT_AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox sh -c \"cat /etc/hostname; echo done\""
AUTO_CMD="${VM_AUTO_CMD:-${1:-$DEFAULT_AUTO_CMD}}"
# 1. Start tmux logging if we are in a tmux pane
if [ -n "$TMUX_PANE" ]; then
    mkdir -p "$LOG_DIR"
    FULL_HISTORY_FILE="$LOG_DIR/live_vm_pane_${TMUX_PANE#%}.log"
    tmux clear-history -t "$TMUX_PANE" 2>/dev/null || true
    clear
    echo "[NaCC][vm-run-start] $(date +%Y%m%d_%H%M%S)"
    echo "[NaCC][vm-live-log] $FULL_HISTORY_FILE"
    echo "Starting background logger for pane $TMUX_PANE..."
    # Running in subshell background loop
    (
        while true; do 
            tmux capture-pane -pt "$TMUX_PANE" -S - > "$FULL_HISTORY_FILE"
            sleep 1
        done
    ) &
    LOGGER_PID=$!
else
    echo "Warning: Not running in tmux, log capture disabled."
fi

# 2. Wait for VM port 2222 and SSH Banner
echo "Waiting for VM (localhost:2222) to operate..."
while true; do
    # Try to connect and read the SSH banner (e.g., "SSH-2.0-OpenSSH...")
    # This ensures sshd is actually running and sending data, not just QEMU listening.
    timeout 2 bash -c 'exec 3<>/dev/tcp/localhost/2222; read -r line <&3; [[ "$line" == SSH* ]]' 2>/dev/null
    
    if [ $? -eq 0 ]; then
        break
    fi
    echo -n "."
    sleep 1
done
echo -e "\nVM is ready! Connecting..."

if ! wait_for_authenticated_ssh; then
    exit 1
fi

# 3. Connect with sshpass and retry on kex_exchange/connection issues
while true; do
    SSH_CMD=("${SSH_BASE_CMD[@]}")

    if [ -n "$AUTO_CMD" ]; then
        echo -e "\033[0;36m[NaCC] Auto-running: $AUTO_CMD\033[0m"
        SSH_CMD=(ssh -tt -p 2222 root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$AUTO_CMD")
    else
        echo -e "\033[0;36m[NaCC] Interactive mode (no auto command)\033[0m"
    fi

    if [ "$HAS_SSHPASS" -ne 1 ]; then
        echo -e "\033[0;31mError: sshpass not found. Falling back to manual password entry.\033[0m"
        run_ssh "${SSH_CMD[@]}"
    else
        if [ -n "$AUTO_CMD" ]; then
            run_ssh_with_timeout "$SSH_AUTO_TIMEOUT_SECONDS" "${SSH_CMD[@]}"
        else
            run_ssh "${SSH_CMD[@]}"
        fi
    fi
    
    EXIT_CODE=$?
    if [ -n "$AUTO_CMD" ]; then
        if [ "$EXIT_CODE" -eq 124 ]; then
            echo "[NaCC][ssh-auto-timeout] remote command exceeded ${SSH_AUTO_TIMEOUT_SECONDS}s"
        else
            echo "[NaCC][ssh-auto-exit] code=$EXIT_CODE"
        fi
    fi
    
    # If ssh exits with 255, it's usually a connection error (reset, timeout)
    # If it exits with 0 (clean logout) or others (command error), we stop retrying.
    if [ $EXIT_CODE -ne 255 ]; then
        break
    fi
    
    echo "Connection reset or failed (Code 255). Retrying in 2s..."
    sleep 2
done
