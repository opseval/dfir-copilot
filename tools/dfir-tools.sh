#!/usr/bin/env bash
#
# Thin wrappers for the dockerized DFIR tools the co-pilot drafts commands for.
# The co-pilot generates a command; you approve; this runs it in a container against
# artifacts in the current directory (mounted read-only at /data).
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

need_docker() { command -v docker >/dev/null 2>&1 || { echo "Docker not found. Install Docker Desktop (./install.sh --with-tools)."; exit 1; }; }
runc() { # runc <image> <args...> : run a tool against $PWD mounted read-only at /data
  need_docker
  local img="$1"; shift
  docker run --rm -v "$PWD":/data:ro -w /data "$img" "$@"
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
  ""|-h|--help) sed -n '2,18p' "$0" ;;
  *) echo "unknown tool/command: $1 (try: list, pull, plaso, vol3, remnux)"; exit 1 ;;
esac
