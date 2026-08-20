#!/usr/bin/env bash
# Publish a scrubbed snapshot to the public git remote (no .cursor/ etc.).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXCLUDE_FILE="${ROOT}/public-sync.exclude"
PUBLIC_REMOTE="${PUBLIC_REMOTE:-public}"
PUBLIC_BRANCH="${PUBLIC_BRANCH:-main}"
WORKTREE="${WORKTREE:-${ROOT}/.public-sync-worktree}"

if [[ ! -f "${EXCLUDE_FILE}" ]]; then
  echo "missing exclude file: ${EXCLUDE_FILE}" >&2
  exit 1
fi

mapfile -t EXCLUDES < <(grep -v '^[[:space:]]*#' "${EXCLUDE_FILE}" | grep -v '^[[:space:]]*$' || true)
if [[ ${#EXCLUDES[@]} -eq 0 ]]; then
  echo "no exclude patterns in ${EXCLUDE_FILE}" >&2
  exit 1
fi

if ! git -C "${ROOT}" remote get-url "${PUBLIC_REMOTE}" >/dev/null 2>&1; then
  echo "git remote '${PUBLIC_REMOTE}' is not configured" >&2
  exit 1
fi

PUBLIC_URL="$(git -C "${ROOT}" remote get-url "${PUBLIC_REMOTE}")"
RSYNC_EXCLUDES=()
for pattern in "${EXCLUDES[@]}"; do
  RSYNC_EXCLUDES+=(--exclude "${pattern}")
done

rm -rf "${WORKTREE}"

if git ls-remote --heads "${PUBLIC_URL}" "${PUBLIC_BRANCH}" | grep -q .; then
  git clone --depth 1 --branch "${PUBLIC_BRANCH}" "${PUBLIC_URL}" "${WORKTREE}"
else
  mkdir -p "${WORKTREE}"
  git -C "${WORKTREE}" init -b "${PUBLIC_BRANCH}"
  git -C "${WORKTREE}" remote add origin "${PUBLIC_URL}"
fi

rsync -a --delete \
  "${RSYNC_EXCLUDES[@]}" \
  --exclude '.git/' \
  --exclude '.public-sync-worktree/' \
  "${ROOT}/" "${WORKTREE}/"

git -C "${WORKTREE}" add -A
if git -C "${WORKTREE}" diff --cached --quiet; then
  echo "public mirror: no changes"
  exit 0
fi

git -C "${WORKTREE}" commit -m "${PUBLIC_COMMIT_MSG:-chore: sync public mirror from private}"
git -C "${WORKTREE}" push origin "${PUBLIC_BRANCH}"

echo "public mirror pushed to ${PUBLIC_URL} (${PUBLIC_BRANCH})"
