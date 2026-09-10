#!/usr/bin/env bash
set -Eeuo pipefail

search_root="${1:-.}"
pattern="(BEGIN ([A-Z0-9][A-Z0-9 -]{0,63} )?PRIVATE KEY( BLOCK)?|[\"']?Authorization[\"']?[[:space:]]*:[[:space:]]*[\"']?[[:space:]]*Bearer[[:space:]]+([-A-Za-z0-9._~+]|\\\\?/){16,}=*|[\"']?client_secret[\"']?[[:space:]]*[:=][[:space:]]*[^[:space:]<]+|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(AKIA|ASIA)[0-9A-Z]{16}|glpat-[A-Za-z0-9_-]{20,})"
path_list="$(mktemp)"
trap 'rm -f -- "$path_list"' EXIT

set +e
find "$search_root" \
  \( -path "$search_root/.git" -o -path "$search_root/upstream" \) -prune -o \
  \( -type f -o -type l \) -print0 > "$path_list"
find_status=$?
set -e
if (( find_status != 0 )); then
  echo "Secret scan traversal failed (find status ${find_status})." >&2
  exit "$find_status"
fi

# Reject every link before inspecting file contents, so a matching secret
# cannot hide a traversal/read error through grep exit-status negation.
while IFS= read -r -d '' path; do
  if [[ -L "$path" ]]; then
    echo "Secret scan refuses symbolic link: ${path}" >&2
    exit 2
  fi
done < "$path_list"

while IFS= read -r -d '' path; do
  set +e
  LC_ALL=C grep -aEiq "$pattern" -- "$path"
  secret_scan_status=$?
  set -e
  case "$secret_scan_status" in
    0)
      echo 'Control-plane secret pattern detected.' >&2
      exit 1
      ;;
    1)
      ;;
    *)
      echo "Secret scan failed before completing (grep status ${secret_scan_status})." >&2
      exit "$secret_scan_status"
      ;;
  esac
done < "$path_list"
