#!/usr/bin/env bash
set -euo pipefail

# SLOC summary for the whole project
# - Excludes common build/cache/output directories
# - Prints per-language counts and a total

# Repo root: parent of the scripts directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. && pwd)"

# Find files for a given pattern, excluding noisy dirs (null-delimited)
find_lang_null() {
  local pattern="$1"
  find "$ROOT_DIR" \
    -type d \
    \( -name .venv -o -name venv -o -name node_modules -o -name .pytest_cache -o -name .ruff_cache -o -name __pycache__ -o -name htmlcov -o -path "$ROOT_DIR/docs/_site" -o -path "$ROOT_DIR/output" -o -path "*/dist" -o -path "*/build" \) -prune \
    -o -type f -name "$pattern" -print0
}

# Return: "<lines> <files>" for pattern
get_count() {
  local pattern="$1"
  local lines=0
  local files=0
  while IFS= read -r -d '' file; do
    local n
    n=$(wc -l < "$file" || echo 0)
    lines=$((lines + n))
    files=$((files + 1))
  done < <(find_lang_null "$pattern")
  echo "$lines $files"
}

echo "🔢 SLOC Summary (excluding docs/_site, caches, dist, build, output)"
echo "Project root: $ROOT_DIR"

read PY_LINES PY_FILES   < <(get_count "*.py")
read JS_LINES JS_FILES   < <(get_count "*.js")
read HTML_LINES HTML_FILES < <(get_count "*.html")
read CSS_LINES CSS_FILES < <(get_count "*.css")
read SH_LINES SH_FILES   < <(get_count "*.sh")

TOTAL_LINES=$((PY_LINES + JS_LINES + HTML_LINES + CSS_LINES + SH_LINES))
TOTAL_FILES=$((PY_FILES + JS_FILES + HTML_FILES + CSS_FILES + SH_FILES))

printf "%-12s files=%-6d lines=%-10d\n" "Python"     "$PY_FILES"   "$PY_LINES"
printf "%-12s files=%-6d lines=%-10d\n" "JavaScript" "$JS_FILES"   "$JS_LINES"
printf "%-12s files=%-6d lines=%-10d\n" "HTML"       "$HTML_FILES" "$HTML_LINES"
printf "%-12s files=%-6d lines=%-10d\n" "CSS"        "$CSS_FILES"  "$CSS_LINES"
printf "%-12s files=%-6d lines=%-10d\n" "Shell"      "$SH_FILES"   "$SH_LINES"

echo "---------------------------------------------"
printf "%-12s files=%-6d lines=%-10d\n" "Total" "$TOTAL_FILES" "$TOTAL_LINES"
