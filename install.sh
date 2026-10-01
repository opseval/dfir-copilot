#!/usr/bin/env bash
#
# DFIR co-pilot — one-command installer for macOS (fresh or existing).
#
#   ./install.sh                 install the co-pilot brain (model + structure stack) and verify
#   ./install.sh --with-tools    also set up a container runtime (Colima, or an existing Docker) + the dockerized DFIR tools (Volatility, Plaso, ...)
#   ./install.sh --no-model      skip the model download (wire everything else)
#   ./install.sh --quick-verify  skip the slow end-to-end model test
#
# It checks what is already present and installs only what is missing. Safe to re-run.
#
set -uo pipefail

# ---------------------------------------------------------------- options
WITH_TOOLS=0; NO_MODEL=0; QUICK_VERIFY=0
for a in "$@"; do case "$a" in
  --with-tools) WITH_TOOLS=1 ;;
  --no-model) NO_MODEL=1 ;;
  --quick-verify) QUICK_VERIFY=1 ;;
  -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  *) echo "unknown option: $a"; exit 1 ;;
esac; done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO/.venv"
PYREQ="3.11"

# ---------------------------------------------------------------- pretty logging
b=$'\033[1m'; g=$'\033[32m'; y=$'\033[33m'; r=$'\033[31m'; c=$'\033[36m'; x=$'\033[0m'
step() { echo; echo "${b}${c}==> $*${x}"; }
ok()   { echo "  ${g}✓${x} $*"; }
info() { echo "  ${c}•${x} $*"; }
warn() { echo "  ${y}!${x} $*"; }
die()  { echo "  ${r}✗ $*${x}"; exit 1; }

echo "${b}DFIR co-pilot installer${x}  (repo: $REPO)"

# ---------------------------------------------------------------- 0. preflight
step "Checking the machine"
[ "$(uname -s)" = "Darwin" ] || die "This installer targets macOS. (Detected $(uname -s).)"
ARCH="$(uname -m)"
if [ "$ARCH" = "arm64" ]; then ok "Apple Silicon (arm64) — ideal for MLX."
else warn "Intel Mac ($ARCH). MLX runs best on Apple Silicon; the co-pilot will be slow but should work."; fi

# ---------------------------------------------------------------- 1. Homebrew
step "Homebrew"
if ! command -v brew >/dev/null 2>&1; then
  info "Homebrew not found — installing (it may ask for your password)..."
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
    || die "Homebrew install failed."
fi
# load brew into THIS shell (arm64 vs Intel prefix)
if [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"
elif [ -x /usr/local/bin/brew ]; then eval "$(/usr/local/bin/brew shellenv)"; fi
command -v brew >/dev/null 2>&1 || die "brew still not on PATH after install."
ok "Homebrew ready ($(brew --version | head -1))"

# ---------------------------------------------------------------- 2. system deps
step "System packages (Python ${PYREQ}, git)"
brew list "python@${PYREQ}" >/dev/null 2>&1 || { info "installing python@${PYREQ}..."; brew install "python@${PYREQ}" || die "python install failed"; }
command -v git >/dev/null 2>&1 || { info "installing git..."; brew install git || die "git install failed"; }
PYBIN="$(brew --prefix "python@${PYREQ}")/bin/python${PYREQ}"
[ -x "$PYBIN" ] || PYBIN="$(command -v python3)"
[ -x "$PYBIN" ] || die "no usable python3 found"
ok "Python: $("$PYBIN" --version) ($PYBIN)"

# ---------------------------------------------------------------- 3. python venv + deps
step "Python environment + dependencies"
if [ ! -d "$VENV" ]; then info "creating virtualenv at .venv ..."; "$PYBIN" -m venv "$VENV" || die "venv creation failed"; fi
# shellcheck disable=SC1091
source "$VENV/bin/activate" || die "failed to activate virtualenv at $VENV"
python -m pip install --quiet --upgrade pip wheel || warn "pip upgrade had warnings (continuing)"
info "installing requirements (mlx-lm, outlines, llguidance, duckdb, huggingface_hub) — this can take a few minutes..."
python -m pip install --quiet -r "$REPO/requirements.txt" || die "pip install of requirements failed"
ok "Python dependencies installed"

# ---------------------------------------------------------------- 4. model
step "Local model (Granite-4.1-3B, MXFP4 ~2.6 GB)"
if [ "$NO_MODEL" = "1" ]; then
  warn "skipping model download (--no-model)"
else
  MODEL_ID="${DFIR_MODEL:-mlx-community/granite-4.1-3b-mxfp4}"
  info "downloading $MODEL_ID (skips files already cached)..."
  python - "$MODEL_ID" <<'PY' || die "model download failed"
import sys
from huggingface_hub import snapshot_download
p = snapshot_download(sys.argv[1])
print("  cached at:", p)
PY
  ok "model ready"
fi

# ---------------------------------------------------------------- 4b. Apple on-device model (optional, macOS 27+)
step "Apple on-device model (optional)"
if command -v fm >/dev/null 2>&1; then
  if fm license --status 2>/dev/null | grep -q '^Agreed'; then
    if fm available --model system 2>&1 | grep -qi '^System model available'; then
      ok "Apple Foundation Models available — routine questions route through it (~3 s); Granite is the fallback"
    else
      warn "Apple Foundation Models not available on this Mac (turn on Apple Intelligence to enable); the Granite path is used"
    fi
  else
    info "run 'fm license' once to enable the Apple on-device model (optional); until then the Granite path is used"
  fi
else
  info "no 'fm' on this macOS (needs macOS 27+); the Granite path is used"
fi

# ---------------------------------------------------------------- 5. launcher + short name
step "Command launcher"
LAUNCH="$REPO/dfir-copilot"
ALIAS="${DFIR_ALIAS-clue}"          # the short global name (export DFIR_ALIAS= to skip it)
cat > "$LAUNCH" <<EOF
#!/usr/bin/env bash
# auto-generated launcher: run the co-pilot inside its venv, from anywhere
export DFIR_PROG="\$(basename "\$0")"   # so --help shows the name you typed (clue or dfir-copilot)
source "$VENV/bin/activate"
export PYTHONPATH="$REPO\${PYTHONPATH:+:\$PYTHONPATH}"
exec python -m copilot.cli "\$@"
EOF
chmod +x "$LAUNCH" || die "could not create launcher at $LAUNCH"
ok "created ./dfir-copilot"
# Put it on PATH without sudo or shell-rc edits (tools/link-launcher.sh: ~/.local/bin if on PATH and
# writable, else Homebrew's bin dir; never overwrites something that is not ours).
GLOBAL_NAME=""                       # set only when every requested name is actually on PATH
LINKERR="$(mktemp)"
LINKDIR="$(bash "$REPO/tools/link-launcher.sh" "$LAUNCH" "$ALIAS" 2>"$LINKERR")"; LINKRC=$?
case "$LINKRC" in
  0) GLOBAL_NAME="${ALIAS:-dfir-copilot}"
     ok "linked into $LINKDIR — run '${GLOBAL_NAME}'$([ -n "$ALIAS" ] && echo " (or 'dfir-copilot')") from anywhere" ;;
  1) warn "linked into $LINKDIR, but: $(tr '\n' ' ' < "$LINKERR")"
     info "rename or remove what is in the way, then re-run ./install.sh" ;;
  2) LINKMSG="$(tr '\n' ' ' < "$LINKERR")"; rm -f "$LINKERR"
     die "${LINKMSG}(set DFIR_ALIAS to a plain name, or DFIR_ALIAS= to skip it)" ;;
  *) info "$(tr '\n' ' ' < "$LINKERR")"
     info "to call it from anywhere, link the launcher into a directory on your PATH, e.g.:"
     info "  [ -e /usr/local/bin/${ALIAS:-dfir-copilot} ] || sudo ln -s '$LAUNCH' /usr/local/bin/${ALIAS:-dfir-copilot}" ;;
esac
rm -f "$LINKERR"

# ---------------------------------------------------------------- 6. optional: Docker + DFIR tools
if [ "$WITH_TOOLS" = "1" ]; then
  step "Container runtime + dockerized DFIR tools (optional)"

  # Rosetta 2 — fast amd64 emulation for the amd64 tool images (Colima --vz-rosetta or Docker Desktop).
  if [ "$ARCH" = "arm64" ]; then
    if /usr/bin/pgrep -q oahd 2>/dev/null; then ok "Rosetta 2 present (for amd64 tools)"
    else info "installing Rosetta 2 (for amd64 EZTools/REMnux containers)..."; softwareupdate --install-rosetta --agree-to-license || warn "Rosetta install skipped/failed"; fi
  fi

  # Pick a container runtime: prefer an EXISTING Colima, then a running/installed Docker engine
  # (Docker Desktop or compatible), else install Colima (open-source/MIT — no Docker Desktop subscription).
  RUNTIME=""
  if command -v colima >/dev/null 2>&1; then
    RUNTIME="colima"; info "using existing Colima runtime"
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    RUNTIME="docker"; ok "using the running Docker engine (Docker Desktop or compatible)"
  elif [ -d "/Applications/Docker.app" ]; then
    RUNTIME="docker"; info "Docker Desktop is installed (engine not running yet)"
  else
    info "no container runtime found — installing Colima (open-source, no Docker Desktop subscription)..."
    brew install colima docker || warn "Colima install failed — install Colima (or Docker) manually"
    RUNTIME="colima"
  fi

  # Colima drives the engine through the standalone docker CLI client; make sure it's present.
  if [ "$RUNTIME" = "colima" ] && ! command -v docker >/dev/null 2>&1; then
    info "installing the docker CLI client (for Colima)..."; brew install docker || warn "docker CLI install failed"
  fi

  # Bring the engine up.
  if [ "$RUNTIME" = "colima" ]; then
    if colima status >/dev/null 2>&1; then ok "Colima already running"
    else
      info "starting Colima..."
      if [ "$ARCH" = "arm64" ]; then
        colima start --vm-type vz --vz-rosetta 2>/dev/null || colima start || warn "colima start failed — run 'colima start' manually"
      else
        colima start || warn "colima start failed — run 'colima start' manually"
      fi
    fi
    docker context use colima >/dev/null 2>&1 || true   # make sure the docker CLI targets Colima
  fi

  # Pull the tool images once the SELECTED engine is actually reachable. For Colima we require
  # `colima status` too, so we never silently pull into a different engine (e.g. a running Docker
  # Desktop) when Colima was chosen but failed to start.
  ENGINE_UP=0
  if [ "$RUNTIME" = "colima" ]; then
    colima status >/dev/null 2>&1 && docker info >/dev/null 2>&1 && ENGINE_UP=1
  else
    docker info >/dev/null 2>&1 && ENGINE_UP=1
  fi
  if [ "$ENGINE_UP" = "1" ]; then
    info "pulling DFIR tool images (large; first pull is slow)..."
    if bash "$REPO/tools/dfir-tools.sh" pull; then ok "DFIR tool images ready"
    else warn "some tool images failed to pull (see above)"; fi
  elif [ "$RUNTIME" = "docker" ]; then
    warn "Docker engine not running — open Docker Desktop (or start your engine), then: ./install.sh --with-tools"
  else
    warn "Colima not reachable — run 'colima start', then: ./install.sh --with-tools"
  fi
else
  info "Skipping dockerized DFIR tools. Add them anytime with: ./install.sh --with-tools"
fi

# ---------------------------------------------------------------- 7. verify
step "Verifying the installation"
VERIFY_ARGS=""; [ "$QUICK_VERIFY" = "1" ] && VERIFY_ARGS="--quick"
if python "$REPO/verify.py" $VERIFY_ARGS; then
  CMD="${GLOBAL_NAME:-./dfir-copilot}"     # the short global name when it was linked, else the in-repo launcher
  step "${g}Done — the DFIR co-pilot is installed and working.${x}"
  cat <<EOF

  Try it:
    ${b}${CMD}${x}                                   # the cheat sheet
    ${b}${CMD} query "how many failed password attempts are there?" copilot/sample/auth_sample.csv${x}
    ${b}${CMD} triage <(echo "services.exe -> cmd.exe -> powershell -enc ...")${x}
    ${b}${CMD} backends${x}

  The model drafts queries and narrates; the deterministic harness owns correctness;
  you approve before anything is acted on. See README.md for the full guide.
EOF
else
  die "verification failed — re-run ./install.sh, or see README.md › Troubleshooting."
fi
