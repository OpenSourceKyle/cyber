#!/bin/bash
# This script retakes the 'gold_image' snapshot from the current VM state.
# It halts the machine and then creates a new snapshot, overwriting the existing one.
#
# USAGE:
#   ./3_retake_gold_snapshot.sh        (Runs in interactive mode, will ask for confirmation)
#   ./3_retake_gold_snapshot.sh -f     (Runs in non-interactive mode, overwrites without asking)
#   ./3_retake_gold_snapshot.sh --force (Same as -f)

set -e

# --- Load shared configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/.config_snapshot"

# --- Get current snapshot list ---
echo "[*] Checking current snapshots..."
SNAPSHOT_LIST=$(vagrant snapshot list)
echo "$SNAPSHOT_LIST"
echo

# --- Check to prompt user or not ---
FORCE_MODE=false
if [[ "$1" == "-f" || "$1" == "--force" ]]; then
  FORCE_MODE=true
  echo "[!] Force mode enabled. The snapshot will be overwritten without confirmation."
else
  # Check if snapshot already exists
  if echo "$SNAPSHOT_LIST" | grep -q "^$SNAPSHOT_NAME "; then
    read -p "    -> This will overwrite the existing '$SNAPSHOT_NAME' snapshot. Are you sure? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      echo "[!] Aborted by user. No snapshot was taken."
      exit 1
    fi
  else
    echo "[*] No existing '$SNAPSHOT_NAME' snapshot found. Proceeding with creation..."
  fi
fi

# --- Main Workflow ---
echo "[*] Step 1: Halting the VM for a clean snapshot..."
vagrant halt
echo "[*] Step 2: Preparing to save the halted state to snapshot '$SNAPSHOT_NAME'..."
vagrant snapshot save $SNAPSHOT_NAME --force

# --- Done ---
echo
echo "[+] SUCCESS: Gold image snapshot retaken successfully."
echo "    To begin working from the clean state, run:"
echo "     vagrant up"
