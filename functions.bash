#!/usr/bin/env bash
# Collection of reusable shell helpers for provisioning and bootstrap workflows.
#
# The file is designed to be sourced by command scripts in ./commands.
# It exposes a superset of the routines that previously lived inline inside
# Terraform templates and startup scripts.

if [[ -n "${__BASH_UTILS_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
__BASH_UTILS_LOADED=1

if [[ "${BASH_SOURCE[0]:-}" == "${0}" ]]; then
  echo "functions.bash is a library and must be sourced (not executed)." >&2
    log_info "Setting up root-to-$target_user shell handoff"

    local handoff_root=/usr/local/lib/coder
    local handoff_script="$handoff_root/root-handoff.sh"

    mkdir -p "$handoff_root"

    cat >"$handoff_script" <<'HANDOFF'
  #!/bin/sh
  # Coder workspace root handoff helper

  TARGET_USER="TARGET_USER_PLACEHOLDER"
  TARGET_DIR="TARGET_DIR_PLACEHOLDER"
  TARGET_SHELL="TARGET_SHELL_PLACEHOLDER"

  # If already running as non-root, just exec the requested shell
  if [ "$(id -u)" -ne 0 ]; then
    exec "$TARGET_SHELL" "$@"
  fi

  # Allow callers to opt-out when root is required (e.g. metrics collectors)
  if [ "${CODER_ALLOW_ROOT:-0}" = "1" ]; then
    exec "$TARGET_SHELL" "$@"
  fi

  # Skip handoff when there is no interactive TTY attached
  if ! [ -t 0 ] || ! [ -t 1 ]; then
    exec "$TARGET_SHELL" "$@"
  fi

  # Skip when invoked by known system daemons
  if command -v ps >/dev/null 2>&1; then
    parent_comm=$(ps -o comm= -p "$PPID" 2>/dev/null || true)
    case "$parent_comm" in
      coder*|ssh*|systemd*|containerd*|dockerd*)
        exec "$TARGET_SHELL" "$@"
        ;;
    esac
  fi

  # Skip when an explicit SSH command is being executed
  if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
    exec "$TARGET_SHELL" "$@"
  fi

  # Change into the target user's home if it exists for a smoother handoff
  if [ -d "$TARGET_DIR" ]; then
    cd "$TARGET_DIR" 2>/dev/null || true
  fi

  export CODER_ALLOW_ROOT=1
  exec su - "$TARGET_USER" -s "$TARGET_SHELL"
  HANDOFF

    sed -i "s|TARGET_USER_PLACEHOLDER|$target_user|g" "$handoff_script"
    sed -i "s|TARGET_DIR_PLACEHOLDER|$target_dir|g" "$handoff_script"
    sed -i "s|TARGET_SHELL_PLACEHOLDER|$target_shell|g" "$handoff_script"
    chmod 0755 "$handoff_script"

    # Ensure the script is an allowed login shell so chsh/usermod can reference it if needed
    if ! grep -Fx "$handoff_script" /etc/shells >/dev/null 2>&1; then
      printf '%s\n' "$handoff_script" >> /etc/shells
    fi

    local hook="\n# coder root handoff\nif [ -x $handoff_script ]; then\n  exec $handoff_script \"\$@\"\nfi\n"
    local rc_files=(
      /root/.profile
      /root/.bash_profile
      /root/.bash_login
      /root/.bashrc
      /root/.zprofile
      /root/.zlogin
      /root/.zshrc
    )

    for rc in "${rc_files[@]}"; do
      touch "$rc"
      if ! grep -q 'coder root handoff' "$rc" 2>/dev/null; then
        printf '%b' "$hook" >>"$rc"
      fi
    done

    log_info "Root handoff configured; interactive root shells will auto-switch to $target_user"
    if has_cmd runuser; then
      runuser -u "$username" -- "$@"
    else
      su - "$username" -s /bin/sh -c "$(printf '%q ' "$@")"
    fi
  fi
}

# Marker helpers -------------------------------------------------------------

_marker_slug() {
  local input=$1
  input=$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]')
  input=$(printf '%s' "$input" | tr -c '[:alnum:]_.-' '_')
  printf '%s' "$input" | tr -s '_' '_'
}

coder_marker_dir() {
  local home=${1:-$HOME}
  [[ -n "$home" ]] || die "coder_marker_dir: home directory not provided"
  printf '%s/.coder_markers' "$home"
}

coder_marker_path() {
  local name=$1
  local version=${2:-1}
  local home=${3:-$HOME}
  local scope=${4:-}
  [[ -n "$name" ]] || die "coder_marker_path requires a marker name"
  local dir
  dir=$(coder_marker_dir "$home")
  local suffix=""
  if [[ -n "$scope" ]]; then
    suffix="__$(_marker_slug "$scope")"
  fi
  printf '%s/%s%s.v%s' "$dir" "$(_marker_slug "$name")" "$suffix" "$version"
}

coder_marker_exists() {
  local name=$1
  local version=${2:-1}
  local home=${3:-$HOME}
  local scope=${4:-}
  local path
  path=$(coder_marker_path "$name" "$version" "$home" "$scope")
  [[ -f "$path" ]]
}

coder_marker_write() {
  local name=$1
  local version=${2:-1}
  local home=${3:-$HOME}
  local scope=${4:-}
  local owner=${5:-}
  local path
  path=$(coder_marker_path "$name" "$version" "$home" "$scope")
  local dir
  dir=$(dirname "$path")
  mkdir -p "$dir"
  printf '%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" >"$path"
  if [[ -n "$owner" ]]; then
    chown "$owner":"$owner" "$dir" "$path" 2>/dev/null || true
  fi
  printf '%s' "$path"
}

coder_marker_remove() {
  local name=$1
  local version=${2:-1}
  local home=${3:-$HOME}
  local scope=${4:-}
  local path
  path=$(coder_marker_path "$name" "$version" "$home" "$scope")
  rm -f "$path" 2>/dev/null || true
}

coder_marker_should_run() {
  local name=$1
  local version=${2:-1}
  local home=${3:-$HOME}
  local scope=${4:-}
  local force=${5:-0}
  if [[ "$force" == "1" ]]; then
    coder_marker_remove "$name" "$version" "$home" "$scope"
    return 0
  fi
  if coder_marker_exists "$name" "$version" "$home" "$scope"; then
    return 1
  fi
  return 0
}

user_home() {
  local username=$1
  [[ -n "$username" ]] || die "user_home requires a username"
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  [[ -n "$home" ]] || die "Unable to determine home directory for $username"
  printf '%s' "$home"
}

# Package management helpers -------------------------------------------------
__BASH_UTILS_PKG_MANAGER=""
__BASH_UTILS_APT_UPDATED=0

_detect_pkg_manager() {
  if [[ -n "$__BASH_UTILS_PKG_MANAGER" ]]; then
    return 0
  fi
  local candidates=(apt-get dnf yum apk pacman zypper brew)
  for candidate in "${candidates[@]}"; do
    if has_cmd "$candidate"; then
      __BASH_UTILS_PKG_MANAGER="$candidate"
      log_debug "Detected package manager: $__BASH_UTILS_PKG_MANAGER"
      return 0
    fi
  done
  die "Unable to detect supported package manager."
}

pkg_install() {
  require_root
  _detect_pkg_manager
  local packages=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --) shift; break ;;
      -*) die "Unsupported option for pkg_install: $1" ;;
      *) packages+=("$1"); shift ;;
    esac
  done

  if [[ ${#packages[@]} -eq 0 ]]; then
    return 0
  fi

  log_info "Installing packages: ${packages[*]}"
  case "$__BASH_UTILS_PKG_MANAGER" in
    apt-get)
      if [[ $__BASH_UTILS_APT_UPDATED -eq 0 ]]; then
      apt-get update -q
        __BASH_UTILS_APT_UPDATED=1
      fi
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        -o Dpkg::Options::="--force-confold" \
        -o Dpkg::Options::="--force-confdef" \
        "${packages[@]}"
      ;;
    dnf)
      dnf install -y "${packages[@]}"
      ;;
    yum)
      yum install -y "${packages[@]}"
      ;;
    apk)
      apk add --no-progress "${packages[@]}"
      ;;
    pacman)
      pacman -Sy --noconfirm "${packages[@]}"
      ;;
    zypper)
      zypper --non-interactive install --force-resolution "${packages[@]}"
      ;;
    brew)
      brew install "${packages[@]}"
      ;;
    *)
      die "Unsupported package manager: $__BASH_UTILS_PKG_MANAGER"
      ;;
  esac
}

ensure_packages() {
  local missing=()
  for pkg in "$@"; do
    if ! has_cmd "$pkg"; then
      missing+=("$pkg")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    pkg_install "${missing[@]}"
  fi
}

# User and group management ---------------------------------------------------

remove_user_by_uid() {
  local uid=$1
  require_root
  if id "$uid" >/dev/null 2>&1; then
    local username
    username=$(id -un "$uid" 2>/dev/null || true)
    log_info "Removing user UID $uid (${username:-unknown})"
    if has_cmd pkill; then
      pkill -u "$uid" >/dev/null 2>&1 || true
    fi
    if [[ -n "$username" ]]; then
      userdel -r "$username" >/dev/null 2>&1 || true
    fi
  fi
}

remove_group_by_gid() {
  local gid=$1
  require_root
  if getent group "$gid" >/dev/null 2>&1; then
    local group
    group=$(getent group "$gid" | cut -d: -f1)
    log_info "Removing group GID $gid (${group:-unknown})"
    if [[ -n "$group" ]]; then
      groupdel "$group" >/dev/null 2>&1 || true
    fi
  fi
}

ensure_group() {
  require_root
  local name=""
  local gid=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name=$2; shift 2 ;;
      --gid) gid=$2; shift 2 ;;
      *) die "Unknown option for ensure_group: $1" ;;
    esac
  done
  [[ -z "$name" ]] && die "ensure_group requires --name"

  if getent group "$name" >/dev/null 2>&1; then
    if [[ -n "$gid" ]]; then
      local current_gid
      current_gid=$(getent group "$name" | cut -d: -f3)
      if [[ "$current_gid" != "$gid" ]]; then
        log_warn "Group $name exists with GID $current_gid (wanted $gid)."
      fi
    fi
    return 0
  fi

  if [[ -n "$gid" ]]; then
    groupadd --gid "$gid" "$name"
  else
    groupadd "$name"
  fi
}

ensure_user() {
  require_root
  local name=""
  local uid=""
  local gid=""
  local shell="/bin/bash"
  local home=""
  local create_home=1

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name=$2; shift 2 ;;
      --uid) uid=$2; shift 2 ;;
      --gid) gid=$2; shift 2 ;;
      --shell) shell=$2; shift 2 ;;
      --home) home=$2; shift 2 ;;
      --no-create-home) create_home=0; shift ;;
      *) die "Unknown option for ensure_user: $1" ;;
    esac
  done

  [[ -z "$name" ]] && die "ensure_user requires --name"

  if id "$name" >/dev/null 2>&1; then
    log_info "User $name already exists"
    return 0
  fi

  if [[ -n "$gid" ]]; then
    ensure_group --name "$name" --gid "$gid"
    gid_option=(--gid "$gid")
  else
    gid_option=()
  fi

  local home_option=()
  if [[ -n "$home" ]]; then
    home_option=(--home-dir "$home")
  fi

  local uid_option=()
  if [[ -n "$uid" ]]; then
    uid_option=(--uid "$uid")
  fi

  local create_flag="--create-home"
  [[ $create_home -eq 0 ]] && create_flag="--no-create-home"

  useradd "$create_flag" "${uid_option[@]}" "${gid_option[@]}" --shell "$shell" "${home_option[@]}" "$name"
  log_info "Created user $name"
}

ensure_user_in_sudoers() {
  require_root
  local username=$1
  local mode=${2:-NOPASSWD}
  ensure_packages sudo

  if ! id "$username" >/dev/null 2>&1; then
    die "User $username does not exist"
  fi

  local entry="$username ALL=(ALL) ${mode}:ALL"
  local sudoers_file="/etc/sudoers.d/${username}-bash-utils"
  if [[ -f "$sudoers_file" ]] && grep -Fq "$entry" "$sudoers_file"; then
    log_info "Sudoers entry already present for $username"
    return 0
  fi

  log_info "Adding sudoers entry for $username ($mode)"
  printf '%s\n' "$entry" > "$sudoers_file"
  chmod 0440 "$sudoers_file"
  visudo -c >/dev/null
}

set_login_shell() {
  require_root
  local username=$1
  local shell_path=$2
  if ! id "$username" >/dev/null 2>&1; then
    die "Cannot set shell; user $username does not exist"
  fi

  if [[ -z "$shell_path" ]]; then
    die "set_login_shell requires a non-empty shell path"
  fi

  # Register shell in /etc/shells if missing
  if ! grep -Fx "$shell_path" /etc/shells >/dev/null 2>&1; then
    log_info "Registering $shell_path in /etc/shells"
    # Ensure /etc/shells exists
    touch /etc/shells 2>/dev/null || true
    printf '%s\n' "$shell_path" >> /etc/shells
  fi

  # Prefer chsh, fall back to usermod, then a safe /etc/passwd edit as last resort.
  if has_cmd chsh; then
    if chsh -s "$shell_path" "$username"; then
      return 0
    else
      log_warn "chsh failed to set shell for $username; trying fallback methods"
    fi
  fi

  if has_cmd usermod; then
    if usermod -s "$shell_path" "$username"; then
      return 0
    else
      log_warn "usermod failed to set shell for $username; trying passwd file edit"
    fi
  fi

  # Final fallback: edit /etc/passwd atomically. This is a last-resort measure.
  if [[ -w /etc/passwd ]]; then
    awk -F: -v user="$username" -v shell="$shell_path" 'BEGIN{OFS=FS} { if ($1==user) $7=shell; print }' /etc/passwd > /etc/passwd.tmp && mv /etc/passwd.tmp /etc/passwd && chmod 644 /etc/passwd
    if grep -q "^${username}:" /etc/passwd && awk -F: -v user="$username" '($1==user){print $7}' /etc/passwd | grep -Fq "$shell_path"; then
      log_info "Set login shell for $username to $shell_path via /etc/passwd edit"
      return 0
    else
      die "Failed to set login shell for $username"
    fi
  else
    die "Unable to modify /etc/passwd to set shell for $username"
  fi
}

ensure_home_skeleton() {
  require_root
  local username=$1
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  [[ -z "$home" ]] && die "Unable to determine home directory for $username"
  mkdir -p "$home"
  if [[ ! -f "$home/.profile" && -d /etc/skel ]]; then
    cp -a /etc/skel/. "$home" >/dev/null 2>&1 || true
  fi
  mkdir -p "$home/.local/bin"
  chown -R "$username":"$username" "$home"
  chmod 755 "$home"
  log_info "Initialized home skeleton for $username"
}

# Git configuration ----------------------------------------------------------

write_git_config() {
  local username=$1
  local git_name=$2
  local git_email=$3
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  [[ -z "$home" ]] && die "Unable to determine home directory for $username"

  cat >"$home/.gitconfig" <<EOF
[user]
    name = $git_name
    email = $git_email
[init]
    defaultBranch = main
[pull]
    rebase = false
EOF
  chown "$username":"$username" "$home/.gitconfig"
  chmod 0644 "$home/.gitconfig"
  log_info "Wrote gitconfig for $username"
}

setup_git_credentials() {
  local username=$1
  local token=$2
  local git_user=${3:-$username}
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  [[ -z "$home" ]] && die "Unable to determine home directory for $username"

  mkdir -p "$home/.config/gh"
  cat >"$home/.config/gh/hosts.yml" <<EOF
github.com:
  oauth_token: "$token"
  user: "$git_user"
EOF
  cat >"$home/.netrc" <<EOF
machine github.com
  login "$git_user"
  password "$token"
EOF
  cat >"$home/.git-credentials" <<EOF
https://$git_user:$token@github.com
EOF
  chown -R "$username":"$username" "$home/.config" "$home/.netrc" "$home/.git-credentials"
  chmod 0600 "$home/.netrc" "$home/.git-credentials"
  chmod 0600 "$home/.config/gh/hosts.yml"
  log_info "Configured GitHub credentials for $username"
}

ensure_branch_exists() {
  local repo_url=""
  local branch=""
  local token=""
  local git_user=""
  local base=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo-url) repo_url=$2; shift 2 ;;
      --branch) branch=$2; shift 2 ;;
      --token) token=$2; shift 2 ;;
      --username) git_user=$2; shift 2 ;;
      --base) base=$2; shift 2 ;;
      --verbose) BASH_UTILS_VERBOSE=1; shift ;;
      *) die "Unknown option for ensure_branch_exists: $1" ;;
    esac
  done

  [[ -z "$repo_url" || -z "$branch" ]] && die "ensure_branch_exists requires --repo-url and --branch"

  ensure_packages git

  local tmpdir
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  log_info "Ensuring branch $branch exists in $repo_url"
  git -C "$tmpdir" init -q --initial-branch main
  git -C "$tmpdir" remote add origin "$repo_url"
  if [[ -n "$token" ]]; then
    git -C "$tmpdir" config credential.helper "!f(){ printf 'username=%s\n' '${git_user:-oauth2}'; printf 'password=%s\n' '$token'; }; f"
  fi
  if git -C "$tmpdir" ls-remote --heads origin "$branch" | grep -q "$branch"; then
    log_info "Branch $branch already exists"
    rm -rf "$tmpdir"
    trap - EXIT
    return 0
  fi
  if [[ -z "$token" ]]; then
    log_warn "Branch missing and no token provided; skipping creation."
    rm -rf "$tmpdir"
    trap - EXIT
    return 0
  fi
  if [[ -z "$base" ]]; then
    base=$(git -C "$tmpdir" ls-remote --symref origin HEAD | sed -n 's/^ref: refs\/heads\///p' | head -n1)
    if [[ -z "$base" ]]; then
      for candidate in main master trunk; do
        if git -C "$tmpdir" ls-remote --heads origin "$candidate" | grep -q "$candidate"; then
          base=$candidate
          break
        fi
      done
    fi
    [[ -z "$base" ]] && die "Unable to determine base branch for $repo_url"
  fi
  log_info "Creating branch $branch from $base"
  git -C "$tmpdir" fetch --depth=1 origin "$base"
  git -C "$tmpdir" checkout -b "$branch" "origin/$base"
  if ! git -C "$tmpdir" push origin "$branch"; then
    log_warn "Push failed (likely read-only token). Branch not created."
  fi
  rm -rf "$tmpdir"
  trap - EXIT
}

# Project scaffolding --------------------------------------------------------

scaffold_python_project() {
  local target_dir=""
  local project_name="Sample Project"
  local owner=""
  local configure_remote=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --path) target_dir=$2; shift 2 ;;
      --name) project_name=$2; shift 2 ;;
      --owner) owner=$2; shift 2 ;;
      --owner=*) owner=${1#*=}; shift ;;
      --no-remote) configure_remote=0; shift ;;
      *) die "Unknown option for scaffold_python_project: $1" ;;
    esac
  done
  [[ -z "$target_dir" ]] && die "scaffold_python_project requires --path"
  [[ -z "$owner" ]] && die "scaffold_python_project requires --owner"
  mkdir -p "$target_dir/src"
  touch "$target_dir/src/main.ipynb"
  cat >"$target_dir/requirements.txt" <<'REQ'
ipykernel
# Add your runtime dependencies here, one per line.
REQ
  if command -v python3 >/dev/null 2>&1; then
    python3 -m venv "$target_dir/.venv"
    "$target_dir/.venv/bin/pip" install --upgrade pip
    "$target_dir/.venv/bin/pip" install -r "$target_dir/requirements.txt"
  fi
  if command -v git >/dev/null 2>&1; then
    git -C "$target_dir" init -q --initial-branch main
    git -C "$target_dir" add .
    git -C "$target_dir" commit -m "Scaffolded directory." -q
    # Configure remote origin unless --no-remote was provided.
    if [[ $configure_remote -eq 1 && -n "$owner" ]]; then
      # Derive repo name from target_dir (basename) and sanitize
      repo_name=$(basename "$target_dir")
      repo_name=${repo_name//:/-}
      repo_name=${repo_name//./-}
      remote_url="https://github.com/${owner}/${repo_name}.git"
      git -C "$target_dir" remote add origin "$remote_url" || git -C "$target_dir" remote set-url origin "$remote_url"
      git -C "$target_dir" branch --set-upstream-to="origin/main" main 2>/dev/null || true
      log_info "Set git remote origin to $remote_url"
    else
      log_info "Skipping remote origin configuration"
    fi
  fi
  cat >"$target_dir/README.md" <<EOF
# $project_name

Scaffold generated by bash-utils.
EOF
  cat >"$target_dir/.gitignore" <<'GITIGNORE'
.venv/
__pycache__/
*.pyc
.ipynb_checkpoints/
GITIGNORE
  log_info "Python scaffold created at $target_dir"
}

# Shell customisation --------------------------------------------------------

install_zsh_for_user() {
  local username=$1
  local theme=${2:-eastwood}
  local style=${3:-minimal}

  log_info "Installing zsh for user $username"
  # Install zsh (best-effort) and report failures with context
  if ! ensure_packages zsh; then
    log_warn "Package install for zsh reported problems. Continuing to attempt configuration but zsh may be missing."
  fi

  ensure_user --name "$username" --shell /bin/bash
  ensure_home_skeleton "$username"

  # Verify zsh is present before changing the login shell
  local zsh_path
  zsh_path=$(command -v zsh 2>/dev/null || true)
  if [[ -z "$zsh_path" ]]; then
    log_error "zsh binary not found after ensure_packages. Detected package manager: $__BASH_UTILS_PKG_MANAGER."
    log_error "Check the container's package manager or install zsh manually (e.g., apt-get install -y zsh)."
    return 1
  fi

  if ! set_login_shell "$username" "$zsh_path"; then
    log_error "Failed to set login shell for $username to $zsh_path"
    return 1
  fi

  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  local zshrc="$home/.zshrc"

  case "$style" in
    minimal)
      cat >"$zshrc" <<EOF
# Generated by bash-utils install_zsh_for_user
export ZSH_THEME="$theme"
PROMPT='%n@%m:%~$ '
setopt HIST_IGNORE_DUPS HIST_REDUCE_BLANKS
autoload -Uz compinit && compinit
EOF
      ;;
    oh-my)
      ensure_oh_my_zsh "$username"
      cat >"$zshrc" <<EOF
# Generated by bash-utils install_zsh_for_user (oh-my-zsh mode)
export ZSH="${home}/.oh-my-zsh"
export ZSH_THEME="$theme"
ZSH_DISABLE_COMPFIX="true"
source "${home}/.oh-my-zsh/oh-my-zsh.sh"
EOF
      ;;
    *)
      die "Unknown zsh install style: $style"
      ;;
  esac

  chown "$username":"$username" "$zshrc"
  chmod 0644 "$zshrc"
  log_info "Configured zsh for $username with theme $theme (style: $style)"
}

ensure_oh_my_zsh() {
  local username=$1
  ensure_packages git curl
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  local omz_dir="$home/.oh-my-zsh"
  if [[ -d "$omz_dir" ]]; then
    log_info "oh-my-zsh already installed for $username"
    return 0
  fi
  log_info "Installing oh-my-zsh for $username"
  if ! run_as_user "$username" git clone --depth=1 https://github.com/ohmyzsh/ohmyzsh "$omz_dir"; then
    log_warn "Failed to clone oh-my-zsh into $omz_dir as $username. Check network access and git credentials (if any)."
    return 1
  fi
}

# VS Code / code-server helpers -----------------------------------------------

write_vscode_settings() {
  local username=$1
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  [[ -z "$home" ]] && die "Unable to determine home directory for $username"
  
  local settings_dir="$home/.vscode-server/data/Machine"
  mkdir -p "$settings_dir"
  
  cat >"$settings_dir/settings.json" <<'EOF'
{
  "github.gitAuthentication": true,
  "git.enabled": true,
  "files.autoSave": "afterDelay",
  "editor.formatOnSave": true,
  "remote.autoForwardPortsSource": "process"
}
EOF
  chown -R "$username":"$username" "$home/.vscode-server"
  log_info "Wrote VS Code settings for $username"
}

install_vscode_extensions() {
  local username=$1
  shift
  local extensions=("$@")
  
  local home
  home=$(getent passwd "$username" | cut -d: -f6)
  [[ -z "$home" ]] && die "Unable to determine home directory for $username"
  
  # Use the user's ~/.vscode-server/extensions as the canonical extensions dir for code-server
  local ext_dir="$home/.vscode-server/extensions"
  local base_vscode_dir="$home/.vscode-server"

  # If ~/.vscode is a symlink, remove it and create a real directory to avoid mismatched ownership.
  if [[ -L "$base_vscode_dir" ]]; then
    log_warn "$base_vscode_dir is a symlink; replacing with a real directory to ensure writable extensions dir"
    unlink "$base_vscode_dir" 2>/dev/null || true
  fi

  mkdir -p "$ext_dir" "$base_vscode_dir" 2>/dev/null || true

  # Ensure ownership and permissions so the workspace user can create extension subdirs.
  chown -R "$username":"$username" "$base_vscode_dir" 2>/dev/null || true
  chmod 0755 "$base_vscode_dir" "$ext_dir" 2>/dev/null || true

  # Ensure extensions.json exists (code-server may try to read it during install).
  if [[ ! -f "$ext_dir/extensions.json" ]]; then
    printf '[]' >"$ext_dir/extensions.json" 2>/dev/null || true
  fi
  chown "$username":"$username" "$ext_dir/extensions.json" 2>/dev/null || true
  chmod 0644 "$ext_dir/extensions.json" 2>/dev/null || true

  log_info "Installing VS Code extensions for $username: ${extensions[*]}"

  # Quick write test as the target user to ensure we won't hit EACCES during installs.
  if ! run_as_user "$username" sh -c "touch '$ext_dir/.coder_ext_test' >/dev/null 2>&1 && rm -f '$ext_dir/.coder_ext_test' >/dev/null 2>&1"; then
    log_warn "Extensions directory $ext_dir is not writable by $username; skipping extension installation"
    return 1
  fi
  
  # Locate a code-server / code CLI to use for installs
  local cs_bin=""
  if [[ -x /tmp/code-server/bin/code-server ]]; then
    cs_bin="/tmp/code-server/bin/code-server"
  elif [[ -x /code-server/bin/code-server ]]; then
    cs_bin="/code-server/bin/code-server"
  elif has_cmd code; then
    cs_bin="$(command -v code)"
  fi

  if [[ -z "$cs_bin" ]]; then
    log_warn "No VS Code CLI found; skipping extension installation"
    return 1
  fi

  # Install each extension with a few retries to handle transient EACCES or network issues.
  for ext in "${extensions[@]}"; do
    # Support remote URLs (http/https) by downloading to a temporary file first.
    local install_target="$ext"
    local _tmp_ext_dir=""
    if printf '%s' "$ext" | grep -Eq '^https?://'; then
      if ! has_cmd curl && ! has_cmd wget; then
        log_warn "No downloader (curl or wget) available to fetch $ext; skipping"
        continue
      fi
      _tmp_ext_dir=$(mktemp -d 2>/dev/null || mktemp -d -t vscode_ext)
      install_target="$_tmp_ext_dir/$(basename "${ext%%[\?\#]*}")"

      # Download with simple retries
      dl_retries=3
      dl_count=0
      dl_ok=0
      while :; do
        if has_cmd curl; then
          if curl -fsSL -o "$install_target" "$ext"; then
            dl_ok=1
            break
          fi
        elif has_cmd wget; then
          if wget -q -O "$install_target" "$ext"; then
            dl_ok=1
            break
          fi
        fi
        dl_count=$((dl_count+1))
        if [[ $dl_count -ge $dl_retries ]]; then
          break
        fi
        sleep $((dl_count*2))
      done

      if [[ $dl_ok -ne 1 || ! -f "$install_target" ]]; then
        log_warn "Failed to download extension from $ext; skipping"
        rm -rf "$_tmp_ext_dir" 2>/dev/null || true
        continue
      fi

      # Make the downloaded file readable by the target user
      # Ensure the temp directory and file are accessible by the target user. mktemp -d creates
      # directories with mode 0700 which can block another user from reading files inside.
      chown -R "$username":"$username" "$_tmp_ext_dir" 2>/dev/null || true
      chmod 0755 "$_tmp_ext_dir" 2>/dev/null || true
      chown "$username":"$username" "$install_target" 2>/dev/null || true
      chmod 0644 "$install_target" 2>/dev/null || true
    fi

    retries=3
    count=0
    while :; do
      if run_as_user "$username" "$cs_bin" --install-extension "$install_target" --extensions-dir "$ext_dir"; then
        break
      fi
      count=$((count+1))
      if [[ $count -ge $retries ]]; then
        log_warn "Failed to install extension $ext after $retries attempts"
        break
      fi
      sleep $((count*2))
    done

    # Clean up any temporary download directory
    if [[ -n "$_tmp_ext_dir" ]]; then
      rm -rf "$_tmp_ext_dir" 2>/dev/null || true
    fi
  done
  
  # No symlinks or syncs; code-server will write directly into ~/.vscode/extensions
  chown -R "$username":"$username" "$ext_dir" 2>/dev/null || true
}

write_vscode_workspace_file() {
  local workspace_file=$1
  local project_dir=$2
  local project_name=${3:-$(basename "$project_dir")}
  
  cat >"$workspace_file" <<EOF
{
  "folders": [
    { "path": "$project_name" }
  ]
}
EOF
  log_info "Wrote VS Code workspace file: $workspace_file"
}

# Repository management ------------------------------------------------------

clone_or_update_repo() {
  local repo_url=""
  local branch="main"
  local target_dir=""
  local token=""
  local username=""
  
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo-url) repo_url=$2; shift 2 ;;
      --branch) branch=$2; shift 2 ;;
      --target-dir) target_dir=$2; shift 2 ;;
      --token) token=$2; shift 2 ;;
      --username) username=$2; shift 2 ;;
      *) die "Unknown option for clone_or_update_repo: $1" ;;
    esac
  done
  
  [[ -z "$repo_url" ]] && die "clone_or_update_repo requires --repo-url"
  [[ -z "$target_dir" ]] && die "clone_or_update_repo requires --target-dir"
  
  ensure_packages git
  
  # Configure credentials if provided
  if [[ -n "$token" ]]; then
    local cred_helper="!f(){ printf 'username=%s\n' '${username:-oauth2}'; printf 'password=%s\n' '$token'; }; f"
    export GIT_CONFIG_COUNT=1
    export GIT_CONFIG_KEY_0="credential.helper"
    export GIT_CONFIG_VALUE_0="$cred_helper"
  fi
  
  mkdir -p "$(dirname "$target_dir")"
  
  if [[ -d "$target_dir/.git" ]]; then
    log_info "Repository exists at $target_dir; updating"
    git -C "$target_dir" remote set-url origin "$repo_url" || true
    git -C "$target_dir" fetch origin || true
    git -C "$target_dir" checkout "$branch" || git -C "$target_dir" checkout -b "$branch"
    git -C "$target_dir" pull --ff-only origin "$branch" || true
  else
    log_info "Cloning $repo_url (branch: $branch) to $target_dir"
    rm -rf "$target_dir"
    if ! git clone --branch "$branch" --single-branch --depth=1 "$repo_url" "$target_dir"; then
      log_warn "Single-branch clone failed; trying full clone"
      git clone "$repo_url" "$target_dir"
      git -C "$target_dir" checkout "$branch" || git -C "$target_dir" checkout -b "$branch"
    fi
  fi
  
  git config --global --add safe.directory "$target_dir" || true
  unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
}

# Root-to-user shell handoff -------------------------------------------------

setup_root_handoff() {
  require_root
  local target_user=${1:-coder}
  local target_dir=${2:-/home/$target_user}
  local target_shell=${3:-/usr/bin/zsh}
  
  log_info "Setting up root-to-$target_user shell handoff"
  
  # The simplest approach: add the handoff to /root/.bashrc and /root/.zshrc
  # These get sourced for interactive login shells
  
  # For bash
  if [[ ! -f /root/.bashrc ]]; then
    touch /root/.bashrc
  fi
  if ! grep -q 'CODER_HANDOFF' /root/.bashrc 2>/dev/null; then
    cat >>/root/.bashrc <<'BASHRC_HOOK'

# Coder root handoff
if [ "$(id -u)" -eq 0 ] && [ -z "${CODER_HANDOFF:-}" ]; then
  # Skip handoff for non-interactive shells
  if [ -z "$PS1" ]; then
    return 0 2>/dev/null || exit 0
  fi
  # Skip if parent is a service
  ppid=$PPID
  if command -v ps >/dev/null 2>&1; then
    pcomm=$(ps -o comm= -p "$ppid" 2>/dev/null || true)
    case "$pcomm" in
      *coder*|sshd|*systemd*|docker*) return 0 2>/dev/null || exit 0 ;;
    esac
  fi
  # Skip if SSH command execution
  [ -n "${SSH_ORIGINAL_COMMAND:-}" ] && return 0 2>/dev/null || exit 0
  
  export CODER_HANDOFF=1
  cd /home/coder 2>/dev/null || true
  exec su - coder -s /bin/zsh
fi
BASHRC_HOOK
  fi
  
  # For zsh
  if [[ ! -f /root/.zshrc ]]; then
    touch /root/.zshrc
  fi
  if ! grep -q 'CODER_HANDOFF' /root/.zshrc 2>/dev/null; then
    cat >>/root/.zshrc <<'ZSHRC_HOOK'

# Coder root handoff
if [ "$(id -u)" -eq 0 ] && [ -z "${CODER_HANDOFF:-}" ]; then
  # Skip handoff for non-interactive shells
  if [ -z "$PS1" ]; then
    return 0 2>/dev/null || exit 0
  fi
  # Skip if parent is a service
  ppid=$PPID
  if command -v ps >/dev/null 2>&1; then
    pcomm=$(ps -o comm= -p "$ppid" 2>/dev/null || true)
    case "$pcomm" in
      *coder*|sshd|*systemd*|docker*) return 0 2>/dev/null || exit 0 ;;
    esac
  fi
  # Skip if SSH command execution
  [ -n "${SSH_ORIGINAL_COMMAND:-}" ] && return 0 2>/dev/null || exit 0
  
  export CODER_HANDOFF=1
  cd /home/coder 2>/dev/null || true
  exec su - coder -s /bin/zsh
fi
ZSHRC_HOOK
  fi
  
  log_info "Root handoff configured in .bashrc and .zshrc; interactive root logins will auto-switch to $target_user"
}

set_zsh_theme() {
  local zshrc_file=$1
  local theme=$2
  
  [[ -z "$zshrc_file" ]] && die "set_zsh_theme requires a .zshrc path"
  [[ -z "$theme" ]] && die "set_zsh_theme requires a theme name"
  
  if [[ ! -f "$zshrc_file" ]]; then
    echo "export ZSH_THEME=\"$theme\"" > "$zshrc_file"
    return 0
  fi
  
  if grep -Eq '^[[:space:]]*(export[[:space:]]+)?ZSH_THEME[[:space:]]*=' "$zshrc_file"; then
    # Try GNU sed with backup, then BSD sed
    if sed -E -i.bak "s|^[[:space:]]*(export[[:space:]]+)?ZSH_THEME[[:space:]]*=.*|export ZSH_THEME=\"$theme\"|" "$zshrc_file" 2>/dev/null; then
      rm -f "$zshrc_file.bak"
    elif sed -E -i '' "s|^[[:space:]]*(export[[:space:]]+)?ZSH_THEME[[:space:]]*=.*|export ZSH_THEME=\"$theme\"|" "$zshrc_file" 2>/dev/null; then
      :
    else
      # Final awk fallback
      awk -v theme="$theme" '
        BEGIN { re="^[[:space:]]*(export[[:space:]]+)?ZSH_THEME[[:space:]]*=" }
        { if ($0 ~ re) { print "export ZSH_THEME=\""theme"\"" } else { print $0 } }
      ' "$zshrc_file" > "$zshrc_file.tmp" && mv "$zshrc_file.tmp" "$zshrc_file"
    fi
  else
    echo "" >> "$zshrc_file"
    echo "export ZSH_THEME=\"$theme\"" >> "$zshrc_file"
  fi
  
  log_info "Set zsh theme to $theme in $zshrc_file"
}
