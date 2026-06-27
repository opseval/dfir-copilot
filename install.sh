#!/usr/bin/env bash
#
# DFIR co-pilot — one-command installer for macOS (fresh or existing).
#
#   ./install.sh                 install the co-pilot brain (model + structure stack) and verify
#   ./install.sh --with-tools    also set up Docker + the dockerized DFIR tools (Volatility, Plaso, ...)
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

# ---------------------------------------------------------------- 5. launcher
step "Command launcher"
LAUNCH="$REPO/dfir-copilot"
cat > "$LAUNCH" <<EOF
#!/usr/bin/env bash
# auto-generated launcher: run the co-pilot inside its venv, from anywhere
source "$VENV/bin/activate"
export PYTHONPATH="$REPO\${PYTHONPATH:+:\$PYTHONPATH}"
exec python -m copilot.cli "\$@"
EOF
chmod +x "$LAUNCH" || die "could not create launcher at $LAUNCH"
ok "created ./dfir-copilot"
# offer a PATH symlink into ~/.local/bin if that dir is on PATH
if echo ":$PATH:" | grep -q ":$HOME/.local/bin:"; then
  mkdir -p "$HOME/.local/bin"; ln -sf "$LAUNCH" "$HOME/.local/bin/dfir-copilot"
  ok "linked into ~/.local/bin (run 'dfir-copilot' from anywhere)"
else
  info "to call it from anywhere, add this repo to PATH or: ln -sf '$LAUNCH' /usr/local/bin/dfir-copilot"
fi

# ---------------------------------------------------------------- 6. optional: Docker + DFIR tools
if [ "$WITH_TOOLS" = "1" ]; then
  step "Dockerized DFIR tools (optional)"
  if [ "$ARCH" = "arm64" ]; then
    if /usr/bin/pgrep -q oahd 2>/dev/null; then ok "Rosetta 2 present (for amd64 tools)"
    else info "installing Rosetta 2 (for amd64 EZTools/REMnux containers)..."; softwareupdate --install-rosetta --agree-to-license || warn "Rosetta install skipped/failed"; fi
  fi
  if ! command -v docker >/dev/null 2>&1; then
    info "Docker not found — installing Docker Desktop (cask)..."
    brew install --cask docker || warn "Docker Desktop install failed — install it manually from docker.com"
    warn "Open Docker Desktop once to start the engine, then re-run: ./install.sh --with-tools"
  fi
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    info "pulling DFIR tool images (large; first pull is slow)..."
    bash "$REPO/tools/dfir-tools.sh" pull || warn "some tool images failed to pull (see above)"
    ok "DFIR tool images ready"
  else
    warn "Docker engine not running — start Docker Desktop, then: ./install.sh --with-tools"
  fi
else
  info "Skipping dockerized DFIR tools. Add them anytime with: ./install.sh --with-tools"
fi

# ---------------------------------------------------------------- 7. verify
step "Verifying the installation"
VERIFY_ARGS=""; [ "$QUICK_VERIFY" = "1" ] && VERIFY_ARGS="--quick"
if python "$REPO/verify.py" $VERIFY_ARGS; then
  step "${g}Done — the DFIR co-pilot is installed and working.${x}"
  cat <<EOF

  Try it:
    ${b}./dfir-copilot query "how many failed password attempts are there?" copilot/sample/auth_sample.csv${x}
    ${b}./dfir-copilot triage <(echo "services.exe -> cmd.exe -> powershell -enc ...")${x}
    ${b}./dfir-copilot verify${x}

  The model drafts queries and narrates; the deterministic harness owns correctness;
  you approve before anything is acted on. See README.md for the full guide.
EOF
else
  die "verification failed — re-run ./install.sh, or see README.md › Troubleshooting."
fi
