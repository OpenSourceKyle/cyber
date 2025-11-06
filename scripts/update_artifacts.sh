#!/bin/bash

# Script to update artifacts and tools
# This script is called by the GitHub Actions workflow on a weekly schedule

set -euo pipefail

# Define the directory where repositories will be stored
TOOLS_DIR="${TOOLS_DIR:-tools}"

# Define the directory where scripts will be stored
SCRIPTS_DIR="${SCRIPTS_DIR:-scripts}"

# List of repositories to clone/update
# Format: repo_url:branch (branch is optional, defaults to master/main)
REPOS=(
  "https://github.com/andrew-d/static-binaries.git:master"
)

# List of scripts/files to download
# Format: url (files will be saved to SCRIPTS_DIR with their original filename)
SCRIPTS=(
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.ps1"
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat"
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe"
  "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.exe"
)

echo "Starting artifact update process..."

# Create tools and scripts directories if they don't exist
mkdir -p "$TOOLS_DIR"
mkdir -p "$SCRIPTS_DIR"

# Function to extract repository name from URL
get_repo_name() {
  local repo_url="$1"
  basename "$repo_url" .git
}

# Function to clone or update a repository
update_repo() {
  local repo_spec="$1"
  local repo_url branch
  
  # Split by colon to get repo URL and branch
  if [[ "$repo_spec" == *":"* ]]; then
    repo_url="${repo_spec%%:*}"
    branch="${repo_spec##*:}"
  else
    repo_url="$repo_spec"
    branch="master"
  fi
  
  local repo_name=$(get_repo_name "$repo_url")
  local repo_path="$TOOLS_DIR/$repo_name"
  
  echo "Processing repository: $repo_name"
  
  if [ -d "$repo_path" ]; then
    echo "  Repository exists, updating..."
    cd "$repo_path"
    # Check if it's a shallow clone and unshallow if needed
    if [ -f ".git/shallow" ]; then
      git fetch --unshallow 2>/dev/null || git fetch --all
    else
      git fetch --all
    fi
    git checkout "$branch" 2>/dev/null || git checkout -b "$branch" "origin/$branch" 2>/dev/null || git checkout master
    git pull origin "$branch" || git pull origin master || true
    cd - > /dev/null
  else
    echo "  Cloning repository..."
    git clone --branch "$branch" --single-branch --depth 1 "$repo_url" "$repo_path" || \
    git clone --branch master --single-branch --depth 1 "$repo_url" "$repo_path" || \
    git clone --single-branch --depth 1 "$repo_url" "$repo_path"
  fi
  
  echo "  ✓ $repo_name updated"
}

# Function to download a script/file
download_script() {
  local script_spec="$1"
  local url dest_path dest_dir
  
  # Split by colon to get URL and destination path (if custom path specified)
  if [[ "$script_spec" == *":"* ]]; then
    url="${script_spec%%:*}"
    dest_path="${script_spec##*:}"
    local full_dest="$dest_path"
    dest_dir=$(dirname "$full_dest")
  else
    url="$script_spec"
    dest_path=$(basename "$url")
    local full_dest="$SCRIPTS_DIR/$dest_path"
    dest_dir="$SCRIPTS_DIR"
  fi
  
  echo "Downloading script: $(basename "$full_dest")"
  
  # Create destination directory if it doesn't exist
  mkdir -p "$dest_dir"
  
  # Download the file
  wget -q --show-progress -O "$full_dest" "$url" || {
    echo "  ✗ Failed to download $url"
    return 1
  }
  
  # Make it executable if it's a shell script, batch file, PowerShell script, or executable
  if [[ "$full_dest" == *.sh ]] || [[ "$full_dest" == *.bat ]] || [[ "$full_dest" == *.ps1 ]] || [[ "$full_dest" == *.exe ]]; then
    chmod +x "$full_dest"
  fi
  
  echo "  ✓ $(basename "$full_dest") downloaded to $dest_path"
}

# Update each repository
for repo in "${REPOS[@]}"; do
  update_repo "$repo"
done

# Download each script
for script in "${SCRIPTS[@]}"; do
  download_script "$script"
done

echo "Artifact update process completed."

