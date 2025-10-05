# Bash Utilities

Reusable shell helpers extracted from our Terraform startup scripts. The library
provides a single `functions.bash` that can be sourced by any workflow plus a
collection of ready-to-run commands in `commands/` for common provisioning
steps.

## Layout

- `functions.bash` – core library with logging, package management, user
  management, Git helpers, GitHub auth, branch automation, scaffolding, VS Code
  configuration, and shell environment setup utilities.
- `commands/` – thin wrappers that expose opinionated workflows such as
  `ensure_sudo`, `install_zsh`, `setup_git_auth`, `setup_vscode`,
  `setup_root_handoff`, etc.
- `tests/smoke.sh` – minimal syntax check to keep scripts linted.

## Getting started

```bash
# Add the command suite to your PATH
export PATH="$(pwd)/lavlab-bash-utils/commands:$PATH"

# Or invoke commands directly
lavlab-bash-utils/commands/ensure_sudo coder --create --uid=1000 --gid=1000
lavlab-bash-utils/commands/install_zsh coder --oh-my-zsh --theme=eastwood
lavlab-bash-utils/commands/setup_vscode coder ms-python.python ms-toolsai.jupyter
```

Most commands require root privileges because they create users, install
packages, or modify `/etc`. Run them via `sudo` (or within your provisioning
context) when necessary.

### Sourcing the library

```bash
# Inside another script
source /path/to/lavlab-bash-utils/functions.bash
log_info "Hello from the shared helpers"
```

## Available commands

| Command | Purpose |
| --- | --- |
| `clone_repo` | Clone or update a Git repository with authentication support. |
| `ensure_branch` | Make sure a Git branch exists, creating it when needed. |
| `ensure_sudo` | Install `sudo` and optionally grant user privileges. |
| `ensure_user` | Create/update a user with specific IDs and shell. |
| `init_home` | Populate a user's home directory skeleton. |
| `install_zsh` | Install zsh (optionally oh-my-zsh) for a user. |
| `scaffold_python` | Generate a minimal Python project template. |
| `set_theme` | Set or update ZSH_THEME in a .zshrc file. |
| `setup_git_auth` | Configure Git identity and GitHub credentials. |
| `setup_root_handoff` | Auto-switch from root to target user on shell login. |
| `setup_vscode` | Configure VS Code settings and install extensions. |
| `write_workspace` | Create a VS Code .code-workspace file. |

## Library functions

The `functions.bash` library provides 50+ functions including:

### Core utilities
- `log_info`, `log_warn`, `log_error`, `die` – Logging
- `has_cmd`, `require_root`, `run_as_user` – Helper utilities

### Package management
- `pkg_install`, `ensure_packages` – Install packages across distros

### User/group management
- `ensure_user`, `ensure_group` – Create/update users and groups

### Git operations
- `setup_git_credentials` – Configure GitHub authentication
- `ensure_branch_exists` – Create branches remotely if needed
- `clone_or_update_repo` – Smart git clone/update with auth

### Python scaffolding
- `scaffold_python_project` – Generate project structure
- Virtual environment setup

### Zsh configuration
- `install_zsh_for_user` – Install zsh for a user
- `ensure_oh_my_zsh` – Install oh-my-zsh framework
- `set_zsh_theme` – Update ZSH_THEME safely

### VS Code / code-server
- `write_vscode_settings` – Create Machine settings.json
- `install_vscode_extensions` – Install extensions via CLI
- `write_vscode_workspace_file` – Generate .code-workspace files

### Shell environment
- `setup_root_handoff` – Root-to-user shell auto-switching

## Quick smoke test

```bash
bash lavlab-bash-utils/tests/smoke.sh
```

The smoke test runs `bash -n` against the library and all commands. Feel free to
extend it with additional linting (e.g. `shellcheck`) as needed.

## Documentation

- `README.md` – This file (overview and quick start)
- `INTEGRATION_NOTES.md` – How to integrate with Terraform templates
- `TERRAFORM_UPDATES.md` – Step-by-step template update guide
- `QUICK_REFERENCE.md` – Detailed command usage examples
- `EXTRACTION_SUMMARY.md` – What was extracted from Terraform
