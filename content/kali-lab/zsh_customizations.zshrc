# --- Zsh Real-time Logging (Local VM Storage Version) ---

if [[ -z "$ZSH_LOGGING_ACTIVE" ]]; then
    export ZSH_LOGGING_ACTIVE=1

    # Save everything to a reliable directory in the user's home folder.
    LOG_DIR_BASE="$HOME/kali_logs"
    mkdir -p "$LOG_DIR_BASE"
    LOG_DATE=$(date +"%Y-%m-%d")

    local RAW_LOG_FILE="$LOG_DIR_BASE/${LOG_DATE}.raw.log"
    local CLEAN_LOG_FILE="$LOG_DIR_BASE/${LOG_DATE}.clean.log"

    touch "$RAW_LOG_FILE"
    touch "$CLEAN_LOG_FILE"

    local SED_CLEANUP_COMMAND="/^Script started/d; /^Script done/d; s/.\x08//g; s/\x1b=//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1b].* //g; s/\r//g"

    tail -f "$RAW_LOG_FILE" | sed -u "$SED_CLEANUP_COMMAND" >> "$CLEAN_LOG_FILE" &
    export ZSH_LOG_TAIL_PID=$!

    print -P "%B%F{green}Session logging to:%f%b
 -> RAW:   %B${RAW_LOG_FILE}%b
 -> CLEAN: %B${CLEAN_LOG_FILE}%b"

    script -qfa "$RAW_LOG_FILE"
    exit
fi

# --- This code runs inside the logged shell ---

zmodload zsh/datetime
autoload -U add-zsh-hook

_zsh_log_command_marker() {
    local command_to_log="$3"
    [[ -z "$command_to_log" ]] && return
    print -r -- "\n##> $(strftime '%Y-%m-%d %H:%M:%S' $EPOCHSECONDS) ## ${command_to_log}" >&2
}
add-zsh-hook preexec _zsh_log_command_marker

zshexit() {
    kill "$ZSH_LOG_TAIL_PID" &>/dev/null
}

# --- opnotes: Focused Note-Taking ---
opnotes() {
    local NOTES_DIR_BASE="$HOME/kali_logs"
    local NOTES_FILE="$NOTES_DIR_BASE/1_opnotes.txt"

    mkdir -p "$NOTES_DIR_BASE"
    touch "$NOTES_FILE"

    local VIM_TIMESTAMP_FUNC="strftime('%Y-%m-%d %H:%M:%S')"
    local VIM_TIMESTAMP_DELIMITER=" -- "
    local F4_TARGET_TEMPLATE="=================================<CR>X.X.X.X -- domain.com -- win/lin x32/x64<CR>=================================<CR><CR>echo 'export TARGET=X.X.X.X' >> ~/.zshrc"
    local F5_INSERT_EXPRESSION="<C-R>=${VIM_TIMESTAMP_FUNC} . '${VIM_TIMESTAMP_DELIMITER}'<CR>"

    vim \
        -c "nnoremap <F5> I${F5_INSERT_EXPRESSION}" \
        -c "inoremap <F5> <Esc>I${F5_INSERT_EXPRESSION}" \
        -c "vnoremap <F5> <Esc>I${F5_INSERT_EXPRESSION}" \
        -c "nnoremap <F4> i${F4_TARGET_TEMPLATE}" \
        -c "inoremap <F4> <Esc>i${F4_TARGET_TEMPLATE}" \
        -c "vnoremap <F4> <Esc>i${F4_TARGET_TEMPLATE}" \
        "$NOTES_FILE"
}
