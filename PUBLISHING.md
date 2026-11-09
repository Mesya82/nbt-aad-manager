# Publish from Ubuntu in WSL2

This project is a **planning scaffold**, not a tested installer. The GitHub repository has **not** been created merely by downloading this ZIP. The intended public repository is `Mesya82/nbt-aad-manager`.

The publishing workflow is designed for **Ubuntu 24.04 or newer in Windows Subsystem for Linux (WSL2)**. It needs Git and GitHub CLI (`gh`), but **does not require Rust, Cargo, SSH access to a car, or administrative rights on Windows**. All commands below run **inside Ubuntu WSL**, not Windows PowerShell.

## 1. Prerequisites

```bash
sudo apt update
sudo apt install -y git unzip ca-certificates
# Install GitHub CLI (gh) in Ubuntu WSL separately if you have not already.
gh --version
```

Sign in to your own GitHub account in WSL (browser/device-code authentication):

```bash
gh auth login --hostname github.com --git-protocol https --web
gh auth status
gh api user --jq .login
```

The user name should be `Mesya82`. Do not paste access tokens or passwords into the project directory. To configure Git to authenticate pushes using GitHub CLI, run:

```bash
gh auth setup-git
```

## 2. Extract the downloaded archive

The easiest option is to copy the ZIP into your WSL home folder. If it is in the Windows Downloads directory, substitute your Windows account name below:

```bash
mkdir -p ~/projects
unzip /mnt/c/Users/<WINDOWS_USERNAME>/Downloads/nbt-aad-manager-wsl.zip -d ~/projects
cd ~/projects/nbt-aad-manager
```

Alternatively, unzip the archive anywhere under your Linux home directory and `cd` to `nbt-aad-manager`. Prefer `~/projects` over `/mnt/c` to avoid file permission, line-ending, and filesystem behavior surprises when using Linux development tools.

## 3. Publish the public repository

```bash
bash tools/publish.sh
```

The script checks tools and GitHub authentication, confirms that you are logged in as `Mesya82`, rejects an existing local `.git` or remote repository of the same name, displays staged files, and requires the literal `PUBLISH` confirmation before initializing Git and creating the remote. It explicitly sets this repository's Git identity *locally* to your GitHub login and a no-reply address, even if corporate credentials are configured globally. It does not change global identity. **Public repository creation is intentional.**

It then creates and pushes `main` to:

https://github.com/Mesya82/nbt-aad-manager

If the script fails *after* creating the remote, inspect `git remote -v`, `git status`, and `gh repo view Mesya82/nbt-aad-manager` rather than rerunning it blindly. The script never force-pushes or replaces an existing repository.

## 4. Handoff to Claude

Connect Claude to the repository and ask it to **read `CLAUDE.md`, `README.md`, and all documents under `docs/`**. Claude must start with the Phase 0 upstream research and simulator/test harness before implementing any hardware-mutating path. The acceptance suite and fault-injection gates in `docs/TEST_STRATEGY.md` are mandatory.

**Safety:** no vehicle connection, SSH unlock, head-unit file writes, or live test is performed by the publishing script. Do not run the scaffold against a vehicle.
