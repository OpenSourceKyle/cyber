#!/bin/bash
#
# This script automates the creation of the 'gold_image' snapshot.
# It provisions, halts, and then snapshots the VM.
#
# USAGE:
#   ./1_create_gold_image.sh        (Runs in interactive mode, will ask for confirmation)
#   ./1_create_gold_image.sh -f     (Runs in non-interactive mode, overwrites without asking)
#   ./1_create_gold_image.sh --force (Same as -f)
#

# Exit immediately if any command fails
set -e

# --- Argument Parsing ---
# Check if the first argument is a force flag.
FORCE_MODE=false
if [[ "$1" == "-f" || "$1" == "--force" ]]; then
  FORCE_MODE=true
  echo "[!] Force mode enabled. The snapshot will be overwritten without confirmation."
fi

# --- Main Workflow ---
echo "[*] Step 1: Provisioning the VM with 'vagrant up'..."
vagrant up --provision

echo "[*] Step 2: Halting the VM for a clean snapshot..."
vagrant halt

echo "[*] Step 3: Preparing to save the halted state to snapshot 'gold_image'..."

# --- Confirmation Logic ---
# If force mode is NOT enabled, ask the user for confirmation.
if [ "$FORCE_MODE" = false ]; then
  # The -n 1 flag reads a single character, -r prevents backslash escapes.
  read -p "    -> This will overwrite any existing 'gold_image' snapshot. Are you sure? (y/n) " -n 1 -r
  echo # Move to a new line after the user's input

  # Check if the reply is not 'y' or 'Y'.
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "[!] Aborted by user. No snapshot was taken."
    exit 1
  fi
fi

# --- Snapshot Execution ---
# This part is reached if the user confirmed or if force mode was enabled.
echo "    -> Saving snapshot 'gold_image'..."
vagrant snapshot save gold_image --force

echo
echo "[+] SUCCESS: Gold image snapshot created successfully."
echo "    Run 'vagrant up' to begin working from the clean state."
