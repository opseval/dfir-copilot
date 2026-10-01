#!/usr/bin/env bash
#
# Thin wrappers for the dockerized DFIR tools the co-pilot drafts commands for.
# The co-pilot generates a command; you approve; this runs it in a container against
# artifacts in the current directory (mounted read-only at /data). Tools cannot write
# there: anything they produce goes to /out, mounted writable from ./out on the host
# (created when a command names /out) -- or from $DFIR_OUT, which is always mounted when
# set, but never the evidence directory or a parent of it (refused).
#
#   tools/dfir-tools.sh pull                 pull all tool images
#   tools/dfir-tools.sh plaso <args...>      run log2timeline/plaso
#   tools/dfir-tools.sh vol3 <args...>       run Volatility 3
#   tools/dfir-tools.sh list                 show configured tools
#
# Images are sensible defaults; override any with an env var (e.g. DFIR_IMG_PLASO=...).
# EZTools / REMnux are amd64 — on Apple Silicon they run via Rosetta 2 (installed by
# install.sh --with-tools) and are slower.
#
set -uo pipefail

IMG_PLASO="${DFIR_IMG_PLASO:-log2timeline/plaso:latest}"
IMG_VOL3="${DFIR_IMG_VOL3:-sk4la/volatility3:latest}"
IMG_REMNUX="${DFIR_IMG_REMNUX:-remnux/remnux-distro:focal}"

need_docker() {
  command -v docker >/dev/null 2>&1 || { echo "No docker CLI found. Run ./install.sh --with-tools (sets up Colima, or uses an existing Docker engine)."; exit 1; }
  docker info >/dev/null 2>&1 || { echo "Container engine not running. Start it with 'colima start' (Colima) or by opening Docker Desktop."; exit 1; }
}
uses_out() { # uses_out <args...> : does any argument name the /out tree? (exactly /out, /out/..., or -opt=/out...)
  local a
  for a in "$@"; do
    case "$a" in /out|/out/*|-*=/out|-*=/out/*) return 0 ;; esac
  done
  return 1
}
runc() { # runc <image> <args...> : run a tool against $PWD mounted read-only at /data (+ /out writable)
  need_docker
  local img="$1"; shift
  local mounts=(-v "$PWD":/data:ro) out="${DFIR_OUT-}" here
  if [ -z "$out" ] && uses_out "$@"; then  # no explicit output dir: ./out, only when the command names /out
    out="$PWD/out"
  fi
  if [ -n "$out" ]; then
    case "$out" in /*) ;; *) out="$PWD/$out" ;; esac   # absolute before any utility sees it (a leading '-' is then harmless)
    mkdir -p -- "$out" || { echo "cannot create output directory: $out" >&2; exit 1; }
    out="$(cd -- "$out" && pwd -P)" || exit 1  # docker needs an absolute (physical) host path
    here="$(pwd -P)"
    case "$here/" in "${out%/}"/*)               # the evidence tree (or an ancestor of it) must never be writable at /out
      echo "refusing to mount $out writable at /out: it contains the evidence directory $here" >&2
      echo "(set DFIR_OUT to a directory outside the evidence, or a subdirectory such as $here/out)" >&2
      exit 1 ;;
    esac
    mounts+=(-v "$out":/out)
  fi
  docker run --rm "${mounts[@]}" -w /data "$img" "$@"
}

case "${1:-}" in
  pull)
    need_docker
    failed=()
    for img in "$IMG_PLASO" "$IMG_VOL3" "$IMG_REMNUX"; do
      echo "==> docker pull $img"
      docker pull "$img" || failed+=("$img")
    done
    if [ "${#failed[@]}" -gt 0 ]; then
      echo "  ! failed to pull: ${failed[*]} (set a different image via env var, e.g. DFIR_IMG_VOL3=...)"
      exit 1
    fi
    ;;
  list)
    echo "  plaso  -> $IMG_PLASO"
    echo "  vol3   -> $IMG_VOL3"
    echo "  remnux -> $IMG_REMNUX"
    ;;
  plaso)  shift; runc "$IMG_PLASO" "$@" ;;
  vol3)   shift; runc "$IMG_VOL3" "$@" ;;
  remnux) shift; runc "$IMG_REMNUX" "$@" ;;
  ""|-h|--help) sed -n '2,20p' "$0" ;;
  *) echo "unknown tool/command: $1 (try: list, pull, plaso, vol3, remnux)"; exit 1 ;;
esac
