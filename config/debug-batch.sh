#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

WAIT_FOR_PANES_SEC=300
WAIT_FOR_AUTO_SEC=480
WAIT_AFTER_AUTO_SEC=400
TAG_PREFIX="batch"
KEEP_WINDOW=0
SESSION_NAME="nacc-batch-$(date +%Y%m%d_%H%M%S)"
SESSION_CREATED=0
BATCH_FAILED=0

declare -a COMMANDS=()
declare -a RESULTS=()

usage() {
	cat <<'EOF'
Usage:
  config/debug-batch.sh --cmd '<command 1>' --cmd '<command 2>' ...
  config/debug-batch.sh --cmd-file <path>

Options:
  --cmd <command>            Add one test command. Can be repeated.
  --cmd-file <path>          Read one command per line from a file.
  --tag-prefix <prefix>      Prefix used for make logger LOG=... (default: batch)
  --session-name <name>      Detached tmux session name (default: nacc-batch-<timestamp>)
  --wait-after-auto <sec>    Extra wait after [NaCC] Auto-running appears (default: 180)
  --keep-window              Keep tmux test-runner window after successful logger
  --help                     Show this help

Notes:
  - A dedicated detached tmux session is created for the whole batch.
  - Every command runs in a fresh tmux test-runner window inside that session.
  - On logger failure, the current window is preserved for inspection.
  - Commands should usually be passed with --cmd to preserve spaces and quotes.
EOF
}

require_arg() {
	local flag="$1"
	local value="${2:-}"
	if [ -z "$value" ]; then
		echo "Missing value for $flag" >&2
		exit 1
	fi
}

add_commands_from_file() {
	local file="$1"
	if [ ! -f "$file" ]; then
		echo "Command file not found: $file" >&2
		exit 1
	fi

	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			''|'#'*)
				continue
				;;
		esac
		COMMANDS+=("$line")
	done < "$file"
}

escape_single_quotes() {
	printf "%s" "$1" | sed "s/'/'\"'\"'/g"
}

wait_for_panes() {
	local window_id="$1"
	local pane_timeout="$2"
	local elapsed=0

	VM_PANE=""
	QEMU_PANE=""
	GDB_PANE=""

	while [ "$elapsed" -lt "$pane_timeout" ]; do
		while read -r pane_id pane_title pane_cmd pane_dead; do
			[ -n "${pane_id:-}" ] || continue
			case "$pane_title" in
				nacc-vm)
					VM_PANE="$pane_id"
					;;
				nacc-qemu)
					QEMU_PANE="$pane_id"
					;;
				nacc-gdb)
					GDB_PANE="$pane_id"
					;;
			esac
		done < <(tmux list-panes -t "$window_id" -F '#{pane_id} #{pane_title} #{pane_current_command} #{pane_dead}' 2>/dev/null || true)

		if [ -n "$VM_PANE" ] && [ -n "$QEMU_PANE" ] && [ -n "$GDB_PANE" ]; then
			return 0
		fi

		sleep 2
		elapsed=$((elapsed + 2))
	done

	return 1
}

wait_for_auto_running() {
	local live_log="$1"
	local auto_timeout="$2"
	local elapsed=0

	while [ "$elapsed" -lt "$auto_timeout" ]; do
		if [ -f "$live_log" ] && grep -Fq '[NaCC] Auto-running:' "$live_log"; then
			return 0
		fi
		sleep 2
		elapsed=$((elapsed + 2))
	done

	return 1
}

print_result_summary() {
	local line
	echo
	echo "Batch session: $SESSION_NAME"
	echo "Summary:"
	for line in "${RESULTS[@]}"; do
		echo "  $line"
	done
}

ensure_batch_session() {
	if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
		echo "tmux session already exists: $SESSION_NAME" >&2
		exit 1
	fi

	tmux new-session -d -s "$SESSION_NAME" -n batch-orchestrator -c "$ROOT_DIR"
	SESSION_CREATED=1
	echo "[batch] detached tmux session created: $SESSION_NAME"
}

cleanup_batch_session() {
	if [ "$KEEP_WINDOW" -eq 0 ] && [ "$SESSION_CREATED" -eq 1 ] && [ "$BATCH_FAILED" -eq 0 ]; then
		tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true
	fi
}

run_one() {
	local index="$1"
	local command="$2"
	local ts tag escaped_cmd window_id startup_pane logger_pane live_log
	local logger_output qemu_log vm_log

	ts="$(date +%Y%m%d_%H%M%S)"
	tag="${TAG_PREFIX}_$(printf '%02d' "$index")_${ts}"

	read -r window_id startup_pane < <(tmux new-window -P -F '#{window_id} #{pane_id}' -t "$SESSION_NAME:" -n test-runner -c "$ROOT_DIR")
	echo
	echo "[batch] run=$index tag=$tag"
	echo "[batch] command: $command"
	echo "[batch] window=$window_id startup_pane=$startup_pane"

	escaped_cmd="$(escape_single_quotes "$command")"
	tmux send-keys -t "$startup_pane" "make debug VM_AUTO_CMD='$escaped_cmd'" C-m

	if ! wait_for_panes "$window_id" "$WAIT_FOR_PANES_SEC"; then
		echo "[batch] failed: pane startup timeout" >&2
		tmux capture-pane -p -t "$startup_pane" -S -120 2>/dev/null || true
		RESULTS+=("run=$index status=pane-timeout tag=$tag window=$window_id")
		BATCH_FAILED=1
		if [ "$KEEP_WINDOW" -eq 0 ]; then
			tmux kill-window -t "$window_id" 2>/dev/null || true
		fi
		return 1
	fi

	live_log="$ROOT_DIR/logs/live_vm_pane_${VM_PANE#%}.log"
	if ! wait_for_auto_running "$live_log" "$WAIT_FOR_AUTO_SEC"; then
		echo "[batch] failed: auto-running timeout" >&2
		tmux capture-pane -p -t "$VM_PANE" -S -120 2>/dev/null || true
		RESULTS+=("run=$index status=auto-timeout tag=$tag window=$window_id vm_pane=$VM_PANE")
		BATCH_FAILED=1
		if [ "$KEEP_WINDOW" -eq 0 ]; then
			tmux kill-window -t "$window_id" 2>/dev/null || true
		fi
		return 1
	fi

	echo "[batch] auto-running detected, waiting ${WAIT_AFTER_AUTO_SEC}s for command output"
	sleep "$WAIT_AFTER_AUTO_SEC"

	logger_pane="$(tmux split-window -P -F '#{pane_id}' -t "$window_id" -c "$ROOT_DIR" 'bash')"
	tmux send-keys -t "$logger_pane" "make logger LOG=$tag" C-m

	logger_output=""
	for _ in $(seq 1 120); do
		logger_output="$(tmux capture-pane -p -t "$logger_pane" -S -40 2>/dev/null || true)"
		if printf "%s" "$logger_output" | grep -Fq 'log saved to'; then
			break
		fi
		sleep 1
	done

	echo "$logger_output"

	qemu_log="$(printf "%s\n" "$logger_output" | sed -n 's/.*QEMU log saved to \([^ ]*\) (.*/\1/p' | tail -n 1)"
	vm_log="$(printf "%s\n" "$logger_output" | sed -n 's/.*VM   log saved to \([^ ]*\) (.*/\1/p' | tail -n 1)"

	if [ -z "$qemu_log" ] || [ -z "$vm_log" ]; then
		echo "[batch] failed: logger did not report both log paths, keeping window for inspection" >&2
		RESULTS+=("run=$index status=logger-failed tag=$tag window=$window_id")
		BATCH_FAILED=1
		return 1
	fi

	RESULTS+=("run=$index status=ok tag=$tag qemu_log=$qemu_log vm_log=$vm_log")

	if [ "$KEEP_WINDOW" -eq 0 ]; then
		tmux kill-window -t "$window_id" 2>/dev/null || true
	fi

	return 0
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--cmd)
			require_arg "$1" "${2:-}"
			COMMANDS+=("$2")
			shift 2
			;;
		--cmd-file)
			require_arg "$1" "${2:-}"
			add_commands_from_file "$2"
			shift 2
			;;
		--tag-prefix)
			require_arg "$1" "${2:-}"
			TAG_PREFIX="$2"
			shift 2
			;;
		--session-name)
			require_arg "$1" "${2:-}"
			SESSION_NAME="$2"
			shift 2
			;;
		--wait-after-auto)
			require_arg "$1" "${2:-}"
			WAIT_AFTER_AUTO_SEC="$2"
			shift 2
			;;
		--keep-window)
			KEEP_WINDOW=1
			shift
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			echo "Unknown argument: $1" >&2
			usage >&2
			exit 1
			;;
	esac
done

if [ "${#COMMANDS[@]}" -eq 0 ]; then
	usage >&2
	exit 1
fi

ensure_batch_session

failed=0
for i in "${!COMMANDS[@]}"; do
	if ! run_one "$((i + 1))" "${COMMANDS[$i]}"; then
		failed=1
	fi
done

print_result_summary
if [ "$KEEP_WINDOW" -eq 1 ] || [ "$BATCH_FAILED" -eq 1 ]; then
	echo "Session kept for inspection: tmux attach -t $SESSION_NAME"
fi
cleanup_batch_session
exit "$failed"
