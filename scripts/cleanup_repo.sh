#!/usr/bin/env bash
# cleanup_repo.sh
# Permanent purge script to remove AI scaffolding, temporary logs, and legacy files.

set -euo pipefail

echo "=========================================================="
echo "          SENTINEL Codebase Purge & Cleanup"
echo "=========================================================="

TARGETS=(
    ".agents"
    ".claude"
    ".Jules"
    "pytest_temp"
    "skills-lock.json"
    "temp.txt"
    "task.md"
    "backend/cli_runner.py"
    "backend/plugin_loader.py"
)

for target in "${TARGETS[@]}"; do
    if [ -e "$target" ] || [ -L "$target" ]; then
        echo "[*] Cleaning target: $target"
        # Standard filesystem remove
        rm -rf "$target"
        # Remove from git track
        git rm -rf --cached --ignore-unmatch "$target" 2>/dev/null || true
    fi
done

echo "[SUCCESS] Local files and git index cleaned."
echo ""
echo "=========================================================="
echo "    INSTRUCTIONS TO RUN 'git filter-repo' TO WIPE SECRETS"
echo "=========================================================="
echo "To permanently wipe private local paths, git commit history,"
echo "or credentials before making the repository public:"
echo ""
echo "1. Install git-filter-repo: 'pip install git-filter-repo'"
echo "2. Define expressions to replace in a text file (e.g. /tmp/replacements.txt):"
echo "   literal:kirito==>[REDACTED_USER]"
echo "   literal:C:\\Users\\kirito==>[REDACTED_PATH]"
echo "3. Execute: 'git filter-repo --replace-text /tmp/replacements.txt --force'"
echo "4. Push changes back to origin: 'git push origin --force --all'"
echo "=========================================================="
