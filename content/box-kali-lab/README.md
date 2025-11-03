# Kali Linux Lab

An automated Kali Linux, pentesting-focused lab environment provisioned with Ansible and managed via Vagrant.

## Prerequisites

- Python 3
- Vagrant
- libvirt (for KVM provider)

## Setup

1. **Install dependencies:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip3 install --requirement requirements.txt
   ansible-galaxy collection install --requirements-file requirements.yml
   ```

2. **Quick Usage:**

   ```bash
   source venv/bin/activate && vagrant up && vagrant ssh
   ```

## Snapshot Management

The project includes helper scripts for managing VM snapshots:

- `1_create_gold_image.sh` - Creates a gold image snapshot after provisioning. Use this to save a clean state after initial setup.
- `2_restore_to_gold.sh` - Restores the VM to the gold image snapshot, discarding all current changes.
- `3_retake_gold.sh` - Retakes the gold image snapshot from the current VM state, useful for updating the baseline.

All scripts support `-f` or `--force` flags for non-interactive mode. The snapshot name is configured in `.config_snapshot`.

To manually check for snapshots like "gold_image", use:
```bash
vagrant snapshot list
```
