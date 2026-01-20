#!/bin/bash

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
AUTO_CMD="docker run --security-opt seccomp=unconfined --rm busybox echo test"

# 1. Start tmux logging if we are in a tmux pane
if [ -n "$TMUX_PANE" ]; then
    echo "Starting background logger for pane $TMUX_PANE..."
    # Running in subshell background loop
    (
        while true; do 
            # Capture the entire history (-S -) to full-history.txt
            tmux capture-pane -pt "$TMUX_PANE" -S - > full-history.txt
            sleep 5
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

# 3. Connect with sshpass and retry on kex_exchange/connection issues
while true; do
    # Prepare SSH command options
    # If AUTO_CMD is set, we use -t to force PTY and chain 'exec bash -l' to keep the session open
    if [ -n "$AUTO_CMD" ]; then
        SSH_OPTS="-t -p 2222 root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -- $AUTO_CMD; exec bash -l"
    else
        SSH_OPTS="-p 2222 root@localhost -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    fi

    if ! command -v sshpass &> /dev/null; then
        echo -e "\033[0;31mError: sshpass not found. Falling back to manual password entry.\033[0m"
        # shellcheck disable=SC2086
        ssh $SSH_OPTS
    else
        # Assume password is 'riscv' as requested
        # shellcheck disable=SC2086
        sshpass -p riscv ssh $SSH_OPTS
    fi
    
    EXIT_CODE=$?
    
    # If ssh exits with 255, it's usually a connection error (reset, timeout)
    # If it exits with 0 (clean logout) or others (command error), we stop retrying.
    if [ $EXIT_CODE -ne 255 ]; then
        break
    fi
    
    echo "Connection reset or failed (Code 255). Retrying in 2s..."
    sleep 2
done
