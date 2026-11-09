#!/usr/bin/env bash
# Publish the planning scaffold from Ubuntu (including WSL2) using GitHub CLI.
# This script never touches a vehicle or requires Rust/Cargo.
set -Eeuo pipefail

readonly TARGET_OWNER='Mesya82'
readonly TARGET_REPO='nbt-aad-manager'
readonly TARGET="${TARGET_OWNER}/${TARGET_REPO}"
readonly ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '==> %s\n' "$*"; }

cd "$ROOT"
command -v git >/dev/null 2>&1 || fail 'Git is missing. Run: sudo apt install -y git'
command -v gh >/dev/null 2>&1 || fail 'GitHub CLI is missing. Install gh in Ubuntu WSL first.'

if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  fail 'GitHub CLI is not authenticated. Run: gh auth login --hostname github.com --git-protocol https --web'
fi

login="$(gh api user --jq '.login')" || fail 'Unable to query authenticated GitHub account.'
[[ "$login" == "$TARGET_OWNER" ]] || fail "Authenticated as '$login', expected '$TARGET_OWNER'. Change accounts with gh auth switch."

[[ ! -e "$ROOT/.git" ]] || fail 'A .git directory/file is already present. Aborting to avoid changing an existing repository.'
if gh repo view "$TARGET" --json name --jq '.name' >/dev/null 2>&1; then
  fail "Remote ${TARGET} already exists. Not overwriting or force-pushing it."
fi

# Do not accidentally publish local secrets or build outputs even if .gitignore changes.
for sensitive in .env .env.local .env.production .ssh .git target backups snapshots; do
  if [[ -e "$sensitive" ]]; then
    fail "Unexpected '${sensitive}' in project root. Remove it from the publishing directory first."
  fi
done

note "Publishing PUBLIC repository: https://github.com/${TARGET}"
printf 'The repository will be public. It must not contain vehicle data, secrets, or backups.\n'
printf 'Type PUBLISH to proceed: '
read -r approval
[[ "$approval" == 'PUBLISH' ]] || fail 'Cancelled: no local Git commit or remote repository created.'

# Always use this account's no-reply identity for the public initial commit,
# even if corporate identity is configured globally in Git. Local-only change.
id="$(gh api user --jq '.id')" || fail 'Could not retrieve GitHub user ID for a no-reply commit email.'
git init --initial-branch=main
git config --local user.name "$login"
git config --local user.email "${id}+${login}@users.noreply.github.com"

git add --all
if [[ -z "$(git diff --cached --name-only)" ]]; then
  fail 'No files to commit.'
fi
note 'Files staged for the first commit:'
git diff --cached --name-only

git commit -m 'docs: bootstrap safety-first NBT-AAD Rust manager'
note 'Creating public GitHub repository and pushing main...'
if ! gh repo create "$TARGET" --public \
  --description 'Experimental Rust NBT-AAD update manager with mandatory backups and simulator-based safety gates' \
  --source . --remote origin --push; then
  fail 'Repository creation/push failed. Check gh auth status, git remote -v, and git status. Do NOT rerun blindly if the remote was already created.'
fi

note "Published: https://github.com/${TARGET}"
note 'Give Claude repository access, then instruct it to read CLAUDE.md and docs/ before implementation.'
