#!/bin/bash
# ============================================================================
# Axios Supply Chain Attack — Detection Script (macOS/Linux)
# ============================================================================
# Checks if your system was affected by the axios@1.14.1 / axios@0.30.4
# supply chain attack that dropped a cross-platform RAT via plain-crypto-js.
#
# Source: StepSecurity, Socket.dev, GitHub Issue #10604
# ============================================================================

echo "============================================"
echo "  Axios Supply Chain Attack — Detection"
echo "============================================"
echo ""

FOUND=0

# Parse command-line arguments
FAST_MODE=0
if [[ "$1" == "--fast" ]]; then
  FAST_MODE=1
  echo "[!] Running in FAST mode (dev paths only)"
  echo ""
fi

# Scan entire machine by default. You can override with: SEARCH_ROOT=/some/path ./axios_check.sh
# In fast mode, only scan common developer paths for speed.
if [ $FAST_MODE -eq 1 ]; then
  SEARCH_ROOT="${SEARCH_ROOT:-/home:/opt:/srv:/root}"
else
  SEARCH_ROOT="${SEARCH_ROOT:-/}"
fi

# Avoid virtual/system mounts that are noisy or not useful for package scanning.
PRUNE_DIRS=(
  "proc"
  "sys"
  "dev"
  "run"
  "snap"
  "var/lib/docker"
)

machine_find() {
  local search_roots="$SEARCH_ROOT"
  local -a prune_args=()
  
  # Build prune arguments
  for prune_dir in "${PRUNE_DIRS[@]}"; do
    prune_args+=(-prune -path "*/$prune_dir" -o)
  done
  
  # If SEARCH_ROOT contains colons, use xargs; otherwise use find directly.
  if [[ "$search_roots" == *":"* ]]; then
    echo "$search_roots" | tr ':' '\n' | xargs -I {} find {} ${prune_args[@]} "$@" 2>/dev/null
  else
    find "$search_roots" ${prune_args[@]} "$@" 2>/dev/null
  fi
}

# --- Check 1: Installed axios version ---
echo "[1/6] Checking installed axios versions across $SEARCH_ROOT ..."
AXIOS_HITS=$(machine_find -type f -path "*/node_modules/axios/package.json" | head -n 200)
if [ -n "$AXIOS_HITS" ]; then
  AFFECTED_AXIOS=$(echo "$AXIOS_HITS" | xargs -r grep -H -E '"version"[[:space:]]*:[[:space:]]*"(1\.14\.1|0\.30\.4)"' 2>/dev/null | head -n 10)
  if [ -n "$AFFECTED_AXIOS" ]; then
    echo "  !! AFFECTED: compromised axios versions found"
    echo "$AFFECTED_AXIOS" | sed 's/^/  /'
    FOUND=1
  else
    echo "  OK: No compromised axios version installed"
  fi
else
  echo "  OK: No axios installations found in scanned paths"
fi

# --- Check 2: Lockfile contains compromised version ---
echo ""
echo "[2/6] Checking lockfiles for compromised versions across $SEARCH_ROOT ..."
PKG_LOCK_HITS=$(machine_find -type f -name "package-lock.json" | head -n 200)
YARN_LOCK_HITS=$(machine_find -type f -name "yarn.lock" | head -n 200)

LOCK_HIT=""
if [ -n "$PKG_LOCK_HITS" ]; then
  LOCK_HIT+=$(echo "$PKG_LOCK_HITS" | xargs -r grep -H -E '"version"[[:space:]]*:[[:space:]]*"(1\.14\.1|0\.30\.4)"' 2>/dev/null | head -n 10)
fi
if [ -n "$YARN_LOCK_HITS" ]; then
  LOCK_HIT+=$'\n'$(echo "$YARN_LOCK_HITS" | xargs -r grep -H -E 'axios@.*(1\.14\.1|0\.30\.4)|version[[:space:]]+"(1\.14\.1|0\.30\.4)"' 2>/dev/null | head -n 10)
fi

if [ -n "$(echo "$LOCK_HIT" | sed '/^[[:space:]]*$/d')" ]; then
  echo "  !! AFFECTED: compromised versions found in lockfiles"
  echo "$LOCK_HIT" | sed '/^[[:space:]]*$/d' | sed 's/^/  /'
  FOUND=1
else
  echo "  OK: Lockfiles clean (or none found in scanned paths)"
fi

# --- Check 3: Lockfile git history ---
echo ""
echo "[3/6] Checking lockfile git history across local repositories..."
GIT_HIT=""
REPO_DIRS=$(machine_find -type d -name ".git" | sed 's#/\.git$##' | head -n 100)
if [ -n "$REPO_DIRS" ]; then
  while IFS= read -r repo; do
    HIT=$(git -C "$repo" log -p -- package-lock.json yarn.lock 2>/dev/null | grep -E "plain-crypto-js" | head -1)
    if [ -n "$HIT" ]; then
      GIT_HIT+="$repo: $HIT"$'\n'
    fi
  done <<< "$REPO_DIRS"
fi

if [ -n "$GIT_HIT" ]; then
  echo "  !! WARNING: plain-crypto-js appeared in lockfile history"
  echo "$GIT_HIT" | head -n 10 | sed 's/^/  /'
  echo "  (Your system MAY have been compromised even if node_modules is clean now)"
  FOUND=1
else
  echo "  OK: No trace in scanned git histories"
fi

# --- Check 4: Malicious dependency in node_modules ---
echo ""
echo "[4/6] Checking for malicious package in node_modules across $SEARCH_ROOT ..."
PLAIN_CRYPTO_HITS=$(machine_find -type d -path "*/node_modules/plain-crypto-js" | head -n 20)
if [ -n "$PLAIN_CRYPTO_HITS" ]; then
  echo "  !! AFFECTED: plain-crypto-js directory found"
  echo "$PLAIN_CRYPTO_HITS" | sed 's/^/  /'
  FOUND=1
else
  echo "  OK: plain-crypto-js not found in scanned node_modules"
  echo "  (Note: The malware self-destructs - absence does NOT guarantee safety)"
fi

# --- Check 5: RAT artifacts on disk ---
echo ""
echo "[5/6] Checking for RAT artifacts..."

# macOS
if [ "$(uname)" = "Darwin" ]; then
  if [ -f "/Library/Caches/com.apple.act.mond" ]; then
    echo "  !! CRITICAL: macOS RAT found at /Library/Caches/com.apple.act.mond"
    ls -la "/Library/Caches/com.apple.act.mond"
    FOUND=1
  else
    echo "  OK: macOS RAT artifact not found"
  fi
fi

# Linux
if [ -f "/tmp/ld.py" ]; then
  echo "  !! CRITICAL: Linux RAT found at /tmp/ld.py"
  ls -la "/tmp/ld.py"
  FOUND=1
else
  echo "  OK: Linux RAT artifact not found"
fi

# --- Check 6: Network connections to C2 ---
echo ""
echo "[6/6] Checking for C2 connections..."
C2_CHECK=$(netstat -an 2>/dev/null | grep "142.11.206.73" || ss -tn 2>/dev/null | grep "142.11.206.73")
if [ -n "$C2_CHECK" ]; then
  echo "  !! CRITICAL: Active connection to C2 server (142.11.206.73)"
  echo "  $C2_CHECK"
  FOUND=1
else
  echo "  OK: No active C2 connections detected"
fi

# DNS check
DNS_CHECK=$(grep -r "sfrclak.com" /var/log/ 2>/dev/null | head -3)
if [ -n "$DNS_CHECK" ]; then
  echo "  !! WARNING: DNS queries to sfrclak.com found in logs"
  FOUND=1
fi

# --- Summary ---
echo ""
echo "============================================"
if [ $FOUND -eq 1 ]; then
  echo "  !! POTENTIAL COMPROMISE DETECTED"
  echo ""
  echo "  Immediate actions:"
  echo "  1. Pin axios to 1.14.0 or 0.30.3"
  echo "  2. rm -rf node_modules && npm ci"
  echo "  3. Rotate ALL credentials (npm tokens, AWS, SSH, API keys)"
  echo "  4. Block sfrclak.com and 142.11.206.73 at firewall"
  echo "  5. If RAT artifacts found: FULL SYSTEM REBUILD"
  echo ""
  echo "  Ref: https://github.com/axios/axios/issues/10604"
else
  echo "  ALL CLEAR — No indicators of compromise found"
  echo ""
  echo "  Preventive steps:"
  echo "  - Pin axios: npm install axios@1.14.0 --save-exact"
  echo "  - Use npm ci (not npm install) in CI/CD"
  echo "  - Set ignore-scripts=true in .npmrc"
  echo "  - Run: npm config set min-release-age 3"
fi
echo "============================================"
echo ""
echo "Usage:"
echo "  ./axios_check.sh              # Scan entire system"
echo "  ./axios_check.sh --fast       # Scan only /home, /opt, /srv, /root (faster)"
echo "  SEARCH_ROOT=/path ./axios_check.sh  # Scan custom path(s) (colon-separated)"
echo "============================================"