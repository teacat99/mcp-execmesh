#!/usr/bin/env bash
# Publish a scrubbed snapshot to the public git remote (no .cursor/ etc.).
#
# Optional tag propagation (v* semver only):
#   git tag v1.0.0 && ./scripts/sync-public.sh
#   PUBLIC_TAG=v1.0.0 ./scripts/sync-public.sh
# Tags are applied to the public mirror HEAD and pushed to trigger GHCR semver builds.
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

push_public_tags() {
  local -a tags=()
  local -a unique_tags=()
  local tag seen

  if [[ -n "${PUBLIC_TAG:-}" ]]; then
    tags+=("${PUBLIC_TAG}")
  fi

  while IFS= read -r tag; do
    [[ -n "${tag}" ]] && tags+=("${tag}")
  done < <(git -C "${ROOT}" tag --points-at HEAD --list 'v*' 2>/dev/null || true)

  if [[ ${#tags[@]} -eq 0 ]]; then
    return 0
  fi

  for tag in "${tags[@]}"; do
    if [[ ! "${tag}" =~ ^v[0-9] ]]; then
      echo "public mirror: skip invalid tag '${tag}' (expected v* semver)" >&2
      continue
    fi

    seen=0
    for existing in "${unique_tags[@]}"; do
      if [[ "${existing}" == "${tag}" ]]; then
        seen=1
        break
      fi
    done
    if [[ "${seen}" -eq 0 ]]; then
      unique_tags+=("${tag}")
    fi
  done

  if [[ ${#unique_tags[@]} -eq 0 ]]; then
    return 0
  fi

  for tag in "${unique_tags[@]}"; do
    if git -C "${WORKTREE}" ls-remote --tags origin "refs/tags/${tag}" | grep -q .; then
      echo "public mirror: tag ${tag} already exists on remote, skip"
      continue
    fi

    if [[ -n "${PUBLIC_TAG_MESSAGE:-}" ]]; then
      git -C "${WORKTREE}" tag -a "${tag}" -m "${PUBLIC_TAG_MESSAGE}"
    else
      git -C "${WORKTREE}" tag "${tag}"
    fi
    git -C "${WORKTREE}" push origin "${tag}"
    echo "public mirror: pushed tag ${tag}"
  done
}

git -C "${WORKTREE}" add -A
if git -C "${WORKTREE}" diff --cached --quiet; then
  echo "public mirror: no file changes"
  push_public_tags
  exit 0
fi

git -C "${WORKTREE}" commit -m "${PUBLIC_COMMIT_MSG:-chore: sync public mirror from private}"
git -C "${WORKTREE}" push origin "${PUBLIC_BRANCH}"
push_public_tags

echo "public mirror pushed to ${PUBLIC_URL} (${PUBLIC_BRANCH})"
