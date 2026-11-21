#!/usr/bin/env bash
# Discover private boxliy/* Git dependencies in source pubspec files and map
# bare mirrors under .git/buildbox-mirrors for offline compile runners.

discover_private_git_repos() {
  local root=$1
  local files=()
  local file
  [[ -d "$root" ]] || return 0
  while IFS= read -r -d '' file; do
    files+=("$file")
  done < <(find -H "$root" -name .git -prune -o -type f \( -name pubspec.yaml -o -name pubspec.lock \) -print0)
  [[ ${#files[@]} -gt 0 ]] || return 0
  awk '
    {
      sub(/#.*/, "")
      if ($0 ~ /^[ \t\r]*(homepage|repository|issue_tracker|documentation)[ \t\r]*:/) {
        next
      }
      line = $0
      while (match(line, /(https:\/\/github\.com\/|ssh:\/\/git@github\.com(:22)?\/|git@github\.com:)boxliy\/[A-Za-z0-9._-]+/)) {
        matched = substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)
        sub(/^(https:\/\/github\.com\/|ssh:\/\/git@github\.com(:22)?\/|git@github\.com:)/, "", matched)
        sub(/\.git$/, "", matched)
        if (matched ~ /^boxliy\/[A-Za-z0-9][A-Za-z0-9._-]*$/) {
          print matched
        }
      }
    }
  ' "${files[@]}" | LC_ALL=C sort -u
}

register_git_mirror() {
  local mirror_path=$1
  local owner=$2
  local repo=$3
  local abs_mirror
  abs_mirror=$(cd "$mirror_path" && pwd)
  local key="url.file://${abs_mirror}.insteadOf"
  git config --global --unset-all "$key" >/dev/null 2>&1 || true
  local variant
  for variant in \
    "https://github.com/${owner}/${repo}.git" \
    "https://github.com/${owner}/${repo}" \
    "git@github.com:${owner}/${repo}.git" \
    "git@github.com:${owner}/${repo}" \
    "ssh://git@github.com/${owner}/${repo}.git" \
    "ssh://git@github.com/${owner}/${repo}"; do
    git config --global --add "$key" "$variant"
  done
}

configure_source_mirrors() {
  local source_root=$1
  local mirrors_root="$source_root/.git/buildbox-mirrors"
  [[ -d "$mirrors_root" ]] || return 0

  local existing_key
  while IFS= read -r existing_key; do
    [[ -n "$existing_key" ]] || continue
    git config --global --unset-all "$existing_key" >/dev/null 2>&1 || true
  done < <(git config --global --name-only --get-regexp '^url\.file://.*/\.git/buildbox-mirrors/.*\.insteadof$' 2>/dev/null || true)

  if [[ -d "$mirrors_root/nib.git" && ! -d "$mirrors_root/boxliy/nib.git" ]]; then
    register_git_mirror "$mirrors_root/nib.git" boxliy nib
  fi

  local mirror_dir owner_dir owner repo_git repo
  for mirror_dir in "$mirrors_root"/*/*.git; do
    [[ -d "$mirror_dir" ]] || continue
    owner_dir=${mirror_dir%/*}
    owner=${owner_dir##*/}
    repo_git=${mirror_dir##*/}
    repo=${repo_git%.git}
    [[ "$owner" =~ ^[A-Za-z0-9._-]+$ && "$repo" =~ ^[A-Za-z0-9._-]+$ ]] || continue
    register_git_mirror "$mirror_dir" "$owner" "$repo"
  done
}
