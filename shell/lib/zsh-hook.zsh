#!/usr/bin/env zsh
# tirith zsh hook
# Overrides accept-line widget to check commands before execution.
# Overrides bracketed-paste widget to check pasted content.

# Guard against double-loading
[[ -n "$_TIRITH_ZSH_LOADED" ]] && return
_TIRITH_ZSH_LOADED=1

# Save original accept-line widget if it exists
if zle -la | grep -q '^accept-line$'; then
  zle -A accept-line _tirith_original_accept_line
fi

_tirith_accept_line() {
  local buf="$BUFFER"

  # Empty input: pass through
  if [[ -z "$buf" ]]; then
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
    return
  fi

  # Run tirith check and capture output.
  # In zle context, stderr doesn't display directly - we must capture and print.
  local output
  output=$(tirith check --shell posix -- "$buf" 2>&1)
  local rc=$?

  if [[ $rc -eq 1 ]]; then
    # Block: show the command that was blocked, print warning, clear line
    print -r -- "$buf"
    [[ -n "$output" ]] && print -r -- "$output"
    BUFFER=""
    zle reset-prompt
  elif [[ $rc -eq 2 ]]; then
    # Warn: print warning then execute
    print -r -- "$buf"
    [[ -n "$output" ]] && print -r -- "$output"
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
  else
    # Allow: execute normally
    zle _tirith_original_accept_line 2>/dev/null || zle .accept-line
  fi
}

zle -N accept-line _tirith_accept_line

# Bracketed paste interception
if zle -la | grep -q '^bracketed-paste$'; then
  zle -A bracketed-paste _tirith_original_bracketed_paste
fi

_tirith_bracketed_paste() {
  # Read the pasted content into CUTBUFFER via the original widget
  local old_buffer="$BUFFER"
  local old_cursor="$CURSOR"
  zle _tirith_original_bracketed_paste 2>/dev/null || zle .bracketed-paste

  # The new content is what was added to BUFFER
  local new_buffer="$BUFFER"
  local pasted="${new_buffer:$old_cursor:$((${#new_buffer} - ${#old_buffer}))}"

  if [[ -n "$pasted" ]]; then
    # Pipe pasted content to tirith paste and capture output
    local output
    output=$(echo -n "$pasted" | tirith paste --shell posix 2>&1)
    local rc=$?

    if [[ $rc -eq 1 ]]; then
      # Block: revert the paste, show what was pasted, then warning
      BUFFER="$old_buffer"
      CURSOR=$old_cursor
      print -r -- "paste> $pasted"
      [[ -n "$output" ]] && print -r -- "$output"
      zle reset-prompt
    elif [[ $rc -eq 2 ]]; then
      # Warn: keep the paste but show warning
      [[ -n "$output" ]] && print -r -- "$output"
    fi
    # Allow (0): keep the paste silently
  fi
}

zle -N bracketed-paste _tirith_bracketed_paste
