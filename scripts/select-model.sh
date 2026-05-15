#!/bin/bash
# Query OpenRouter for best free chat model, cache result for 24h.
# Output: "deepseek/deepseek-v4-flash:free" (or current best)
# Usage: MODEL=$(bash select-model.sh)

CACHE_FILE="${HOME}/.hermes/depguard-model.txt"
CACHE_TTL=$((24 * 3600))

usage() {
    cat <<'USAGE'
Usage: select-model.sh

Prints the selected OpenRouter model.
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
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

mkdir -p "$(dirname "$CACHE_FILE")"

if [ -f "$CACHE_FILE" ] && [ $(($(date +%s) - $(stat -c %Y "$CACHE_FILE"))) -lt "$CACHE_TTL" ]; then
    cat "$CACHE_FILE"
    exit 0
fi

# Fallback: ranked list of known good free chat models (updated May 2026)
FALLBACK_MODELS=(
    "deepseek/deepseek-v4-flash:free"
    "openrouter/owl-alpha"
    "openrouter/pareto-code"
    "openrouter/auto"
    "nousresearch/hermes-3-llama-3.1-405b:free"
)

MODELS_JSON=$(curl -sf --max-time 10 "https://openrouter.ai/api/v1/models" 2>/dev/null)

if [ -z "$MODELS_JSON" ]; then
    BEST="${FALLBACK_MODELS[0]}"
    echo "$BEST" | tee "$CACHE_FILE"
    echo "⚠️  OpenRouter API unreachable. Using fallback: $BEST" >&2
    exit 0
fi

BEST=$(echo "$MODELS_JSON" | python3 -c '
import json, sys

data = json.load(sys.stdin)
free_chat = []

# Patterns for non-chat models (audio gen, image gen, embeddings, etc.)
NON_CHAT = ["music", "audio", "song", "lyria", "image", "video",
            "embedding", "rerank", "moderation", "whisper", "tts", "speech"]

for m in data.get("data", []):
    price = m.get("pricing", {})
    if float(price.get("prompt", "1")) > 0: continue
    if float(price.get("completion", "1")) > 0: continue
    
    name = m.get("id", "")
    name_lower = name.lower()
    desc = (m.get("description", "") + m.get("name", "")).lower()
    ctx = int(m.get("context_length", 0))
    
    # Exclude non-chat models
    if any(p in name_lower or p in desc for p in NON_CHAT):
        continue
    
    # Scoring
    ctx_score = min(ctx / 1_000_000, 1.0) * 30
    agent_score = 30 if any(k in name_lower for k in ["hermes", "owl", "agent"]) else \
                  20 if any(k in name_lower for k in ["deepseek", "qwen", "gemma", "nemotron"]) else 10
    speed_score = 15 if any(k in name_lower for k in ["flash", "lite", "mini"]) else 0
    ctx_bonus = 10 if ctx >= 1_000_000 else (5 if ctx >= 256_000 else 0)
    
    total = ctx_score + agent_score + speed_score + ctx_bonus
    free_chat.append((total, name, ctx))

free_chat.sort(key=lambda x: (x[0], x[2]), reverse=True)

if free_chat:
    print(free_chat[0][1])  # best model ID
else:
    print("deepseek/deepseek-v4-flash:free")  # hard fallback
')

echo "$BEST" | tee "$CACHE_FILE"
echo "✅ Selected model: $BEST" >&2
