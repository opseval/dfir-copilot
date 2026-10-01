#!/usr/bin/env bash
#
# Link the co-pilot launcher onto PATH -- under `dfir-copilot` and an optional short alias -- without
# sudo, without shell-rc edits, and without ever clobbering something that is not ours.
#
#   tools/link-launcher.sh <launcher> [<alias>]
#
# Directory: ~/.local/bin if it is on PATH and can be created/written, else Homebrew's bin directory
# if it exists, is writable and is on PATH. A destination that already exists is left alone unless it
# is a symlink to exactly this launcher (then it is already right).
#
# stdout: the directory used. stderr: anything refused. Exit 0 = every requested name is linked,
# 1 = a name was refused (something else is there), 2 = invalid alias, 3 = no usable directory.
set -uo pipefail

LAUNCH="${1:?usage: link-launcher.sh <launcher> [<alias>]}"
ALIAS="${2-}"

if [ -n "$ALIAS" ] && ! printf '%s' "$ALIAS" | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]*$'; then
  echo "invalid alias '$ALIAS': use letters, digits, '.', '_' or '-' (no path separators)" >&2
  exit 2
fi
case "$LAUNCH" in /*) ;; *) echo "launcher path must be absolute: $LAUNCH" >&2; exit 2;; esac
[ -x "$LAUNCH" ] || { echo "launcher is not executable: $LAUNCH" >&2; exit 2; }

on_path() { case ":${PATH-}:" in *":$1:"*) return 0;; esac; return 1; }

pick_dir() {
  local d="$HOME/.local/bin" prefix
  if on_path "$d" && mkdir -p "$d" 2>/dev/null && [ -w "$d" ]; then printf '%s\n' "$d"; return 0; fi
  prefix="$(brew --prefix 2>/dev/null)" || prefix=""
  if [ -n "$prefix" ] && [ -d "$prefix/bin" ] && [ -w "$prefix/bin" ] && on_path "$prefix/bin"; then
    printf '%s\n' "$prefix/bin"; return 0
  fi
  return 1
}

link_one() {   # link_one <dir> <name>
  local dest="$1/$2"
  if [ -L "$dest" ] && [ "$(readlink "$dest")" = "$LAUNCH" ]; then return 0; fi     # already ours
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    echo "not linking $dest: something else is already there (left untouched)" >&2
    return 1
  fi
  ln -s "$LAUNCH" "$dest" || { echo "could not create $dest" >&2; return 1; }
}

DIR="$(pick_dir)" || { echo "no writable directory on PATH (tried ~/.local/bin and Homebrew's bin)" >&2; exit 3; }
rc=0
link_one "$DIR" dfir-copilot || rc=1
if [ -n "$ALIAS" ]; then link_one "$DIR" "$ALIAS" || rc=1; fi
printf '%s\n' "$DIR"
exit $rc
