+++
title = "tmux"
+++

- [Ippsec Tmux Video Tutorial](https://www.youtube.com/watch?v=Lqehvpe_djs)
- [Ippsec Tmux Cheat Sheet](https://mavericknerd.github.io/knowledgebase/ippsec/tmux/)

## Install and Setup

Install [Tmux Plugin Manager (TPM)](https://github.com/tmux-plugins/tpm):

```bash
sudo apt install -y tmux
cat > ~/.tmux.conf <<'EOF'
set -g history-limit 50000
run-shell 'mkdir -p ~/.tmux/logs'
set-hook -g after-new-session 'pipe-pane -o "cat >> ~/.tmux/logs/$(date +%Y%m%d-%H%M%S)-#{session_name}-#{window_index}-#{pane_index}.log"'
set-hook -g after-new-window 'pipe-pane -o "cat >> ~/.tmux/logs/$(date +%Y%m%d-%H%M%S)-#{session_name}-#{window_index}-#{pane_index}.log"'
set-hook -g after-split-window 'pipe-pane -o "cat >> ~/.tmux/logs/$(date +%Y%m%d-%H%M%S)-#{session_name}-#{window_index}-#{pane_index}.log"'
set -g @plugin 'tmux-plugins/tpm'
set -g @plugin 'tmux-plugins/tmux-sensible'
set -g @plugin 'tmux-plugins/tmux-sessionist'
set -g @plugin 'tmux-plugins/tmux-pain-control'
set -g @plugin 'tmux-plugins/tmux-resurrect'
run '~/.tmux/plugins/tpm/tpm'
EOF
[ ! -d ~/.tmux/plugins/tpm ] && git clone https://github.com/tmux-plugins/tpm ~/.tmux/plugins/tpm
export TMUX_PLUGIN_MANAGER_PATH="$HOME/.tmux/plugins/"
tmux start-server
tmux new-session -d
$TMUX_PLUGIN_MANAGER_PATH/tpm/bin/install_plugins
tmux kill-server
```

## Tmux Core Hotkeys

*Default Prefix: `Super` key (`CTRL+B`)*

| Action | Hotkey | Description |
| :--- | :--- | :--- |
| **Create New Tab (Window)** | `Prefix` + `C` | Creates a new tmux window (full-screen tab). |
| **Next Tab** | `Prefix` + `N` | Switches to the next tmux window. |
| **Previous Tab** | `Prefix` + `P` | Switches to the previous tmux window. |
| **Switch by Number** | `Prefix` + `0-9` | Jumps directly to a window by index. |
| **Rename Current Tab** | `Prefix` + `,` | Renames the current window for easier tracking. |

## [Tmux Logging](https://github.com/tmux-plugins/tmux-logging) Hotkeys

*Note: Logging is enabled by default in this config via `pipe-pane`, with one timestamped file per pane in `~/.tmux/logs/` (format: `YYYYmmdd-HHMMSS-session-window-pane.log`). The plugin hotkeys below are still useful for manual/retroactive captures. See docs for [changing plugin logging options](https://github.com/tmux-plugins/tmux-logging/blob/master/docs/configuration.md).*

| Action | Hotkey | Description |
| :--- | :--- | :--- |
| **Toggle Logging** | `Super` + `Shift` + `P` | Starts/stops logging the current pane to a file. |
| **Retroactive Log** | `Super` + `Alt` + `Shift` + `P` | Saves the entire pane history (up to `history-limit`) if you forgot to start logging initially. |
| **Pane Capture** | `Super` + `Alt` + `P` | Saves only the *currently visible* screen. Solves copy/paste formatting messes when panes are split. |
