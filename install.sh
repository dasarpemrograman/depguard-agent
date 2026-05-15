#!/bin/bash
set -euo pipefail

echo "🔒 DepGuard Agent — Installer"
echo "=============================="

OPENROUTER_KEY="${OPENROUTER_API_KEY:-}"
HERMES_VERSION="${HERMES_VERSION:-v2026.5.7}"
HERMES_BIN="${HOME}/.hermes/hermes-agent/venv/bin"

usage() {
  cat <<'USAGE'
Usage: install.sh [--openrouter-key KEY] [--hermes-version TAG]

Options:
  --openrouter-key KEY   Save KEY to ~/.hermes/.env for OpenRouter.
  --hermes-version TAG   Hermes git tag to install (default: v2026.5.7).
  -h, --help             Show this help.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --openrouter-key)
      if [ "${2:-}" = "" ]; then
        echo "Error: --openrouter-key requires a value." >&2
        exit 2
      fi
      OPENROUTER_KEY="$2"
      shift 2
      ;;
    --openrouter-key=*)
      OPENROUTER_KEY="${1#*=}"
      shift
      ;;
    --hermes-version)
      if [ "${2:-}" = "" ]; then
        echo "Error: --hermes-version requires a value." >&2
        exit 2
      fi
      HERMES_VERSION="$2"
      shift 2
      ;;
    --hermes-version=*)
      HERMES_VERSION="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

# --- System deps ---
install_with_apt() {
  if command -v sudo >/dev/null 2>&1; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq "$@"
  else
    apt-get update -qq
    apt-get install -y -qq "$@"
  fi
}

missing_deps=()
for dep in git curl python3 node npm jq; do
  if ! command -v "$dep" >/dev/null 2>&1; then
    missing_deps+=("$dep")
  fi
done

if [ "${#missing_deps[@]}" -gt 0 ]; then
  if command -v apt-get >/dev/null 2>&1; then
    install_with_apt git curl python3 python3-pip python3-venv nodejs npm jq
  else
    echo "⚠️  Missing required tools: ${missing_deps[*]}" >&2
    echo "   Install them with your system package manager, then rerun install.sh." >&2
    exit 1
  fi
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    install_with_apt python3-venv
  else
    echo "⚠️  python3 venv support is missing. Install python3-venv or your distro equivalent." >&2
    exit 1
  fi
fi

if ! command -v gh >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    if ! install_with_apt gh; then
      echo "⚠️  GitHub CLI (gh) is required but was not available from apt." >&2
      echo "   Install it from https://cli.github.com/ for your OS, then rerun install.sh." >&2
      exit 1
    fi
  else
    echo "⚠️  GitHub CLI (gh) is required and was not found." >&2
    echo "   Install it from https://cli.github.com/ for your OS, then rerun install.sh." >&2
    exit 1
  fi
fi

# --- Hermes Agent ---
if [ ! -d ~/.hermes/hermes-agent ]; then
  git clone --branch "$HERMES_VERSION" --depth=1 https://github.com/NousResearch/hermes-agent.git ~/.hermes/hermes-agent
  cd ~/.hermes/hermes-agent
  python3 -m venv venv
  source venv/bin/activate
  pip install -e .
else
  echo "Hermes Agent already installed, skipping."
fi

# --- OpenRouter config ---
mkdir -p ~/.hermes

if [ -n "$OPENROUTER_KEY" ]; then
  umask 077
  cat > ~/.hermes/.env << EOF
OPENROUTER_API_KEY=$OPENROUTER_KEY
EOF
  chmod 600 ~/.hermes/.env
  echo "✅ OpenRouter key saved."
else
  echo "⚠️  No OpenRouter key provided. Set OPENROUTER_API_KEY in ~/.hermes/.env manually."
fi

# --- DepGuard skills ---
mkdir -p ~/.hermes/skills/depguard
cp -r skills/depguard/* ~/.hermes/skills/depguard/
echo "✅ DepGuard skills installed."

# --- DepGuard config ---
cp config.yaml ~/.hermes/depguard-config.yaml
chmod 600 ~/.hermes/depguard-config.yaml
echo "✅ DepGuard config installed at ~/.hermes/depguard-config.yaml"

# --- CLI helpers ---
chmod +x scripts/select-model.sh scripts/depguard-run scripts/depguard-monitor scripts/depguard-parse-lockfile scripts/depguard-osv-query scripts/depguard-github-advisories scripts/check-reachability.py scripts/depguard-dashboard scripts/depguard-webhook
mkdir -p ~/.hermes/bin ~/.local/bin
cp scripts/select-model.sh scripts/depguard-parse-lockfile scripts/depguard-osv-query scripts/depguard-github-advisories scripts/check-reachability.py scripts/depguard-dashboard scripts/depguard-webhook ~/.hermes/bin/
cp scripts/depguard-run scripts/depguard-monitor ~/.local/bin/
chmod +x ~/.hermes/bin/select-model.sh ~/.hermes/bin/depguard-parse-lockfile ~/.hermes/bin/depguard-osv-query ~/.hermes/bin/depguard-github-advisories ~/.hermes/bin/check-reachability.py ~/.hermes/bin/depguard-dashboard ~/.hermes/bin/depguard-webhook ~/.local/bin/depguard-run ~/.local/bin/depguard-monitor
echo "✅ depguard-run installed at ~/.local/bin/depguard-run"

# --- PATH setup ---
ensure_path_line() {
  local file="$1"
  local line="$2"
  touch "$file"
  if ! grep -Fqx "$line" "$file"; then
    printf '\n%s\n' "$line" >> "$file"
  fi
}

ensure_path_line "${HOME}/.profile" "export PATH=\"${HERMES_BIN}:${HOME}/.hermes/bin:${HOME}/.local/bin:\$PATH\""
if [ -n "${BASH_VERSION:-}" ]; then
  ensure_path_line "${HOME}/.bashrc" "export PATH=\"${HERMES_BIN}:${HOME}/.hermes/bin:${HOME}/.local/bin:\$PATH\""
fi
export PATH="${HERMES_BIN}:${HOME}/.hermes/bin:${HOME}/.local/bin:${PATH}"
echo "✅ Hermes and DepGuard helper paths added to shell profile."

# --- GitHub CLI auth check ---
if ! gh auth status &>/dev/null; then
  echo ""
  echo "⚠️  GitHub CLI is not authenticated yet."
  echo "   During onboarding, DepGuard will run: gh auth login --with-token"
  echo "   Provide a PAT with 'repo' scope when prompted by the agent."
fi

echo ""
echo "✅ DepGuard Agent installed!"
echo ""
echo "   Quick start:"
echo "   depguard-run"
echo "   depguard-monitor --token ghp_xxxx --repos user/repo1,user/repo2"
echo "   @DepGuard onboard token:ghp_xxxx repos:user/repo1,user/repo2"
echo ""
