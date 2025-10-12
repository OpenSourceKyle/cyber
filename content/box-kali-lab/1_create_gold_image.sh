#!/bin/bash
# This script automates the creation of the 'gold_image' snapshot.
# It provisions, halts, and then snapshots the VM.
#
# USAGE:
#   ./1_create_gold_image.sh        (Runs in interactive mode, will ask for confirmation)
#   ./1_create_gold_image.sh -f     (Runs in non-interactive mode, overwrites without asking)
#   ./1_create_gold_image.sh --force (Same as -f)

set -e

# --- Configuration ---
SNAPSHOT_NAME="gold_image"

# --- Check to prompt user or not ---
FORCE_MODE=false
if [[ "$1" == "-f" || "$1" == "--force" ]]; then
  FORCE_MODE=true
  echo "[!] Force mode enabled. The snapshot will be overwritten without confirmation."
else
  # Check if snapshot already exists
  if vagrant snapshot list | grep -q "^$SNAPSHOT_NAME "; then
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
echo "[*] Step 1: Provisioning the VM with 'vagrant up'..."
vagrant up --provision
echo "[*] Step 2: Halting the VM for a clean snapshot..."
vagrant halt
echo "[*] Step 3: Preparing to save the halted state to snapshot '$SNAPSHOT_NAME'..."
vagrant snapshot save $SNAPSHOT_NAME --force

# --- Done ---
echo
echo "[+] SUCCESS: Gold image snapshot created successfully."
echo "    To begin working from the clean state, run:"
echo "     vagrant up"
