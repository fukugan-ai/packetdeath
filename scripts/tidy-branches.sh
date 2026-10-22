#!/usr/bin/env bash
# Remove finished branches and worktrees, and refuse to remove anything else.
#
# 🔴 The measurement comes first, every time:
#
#   git rev-list --left-right --count <trunk>...<branch>
#
# The right-hand number is what the branch has that the trunk does not. Unless
# it is zero the branch carries unmerged work, and deleting it would throw that
# work away. This script never uses `git branch -D` and never `rm -rf` on a
# worktree (git's own bookkeeping would then point at a directory that is gone).
#
# Usage:
#   scripts/tidy-branches.sh                         dry run: report only
#   scripts/tidy-branches.sh --remove                remove what the report marks removable
#   scripts/tidy-branches.sh --remove-worktree PATH  remove one named worktree, after measuring it
#
# The root is the repository this script lives in. The trunk is `main`.
#
# A branch worktree goes only when its branch has no commit of its own and the
# trunk contains its tip. Undo: `git worktree add <path> <branch>`; the branch
# is never touched by a worktree removal.
# A detached worktree goes only when the trunk contains its tip (the tip is an
# ancestor of the trunk, or the tip's tree appears in the trunk's history), the
# trunk exists, and nothing is uncommitted inside. Undo:
# `git worktree add --detach <path> <tip>`, printed at removal time.
set -euo pipefail

# The root is derived from the script's own location, never spelled out, so
# renaming the directory cannot leave this script pointing at nothing.
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly trunk="main"
remove="no"
[ "${1:-}" = "--remove" ] && remove="yes"

cd "$root"

# 🔴 A branch with zero commits of its own also has a right-hand count of
# zero, and that is "not started", not "merged": a builder may be working in
# it right now. The tip's position cannot tell the two apart (a fast-forward
# merge leaves the tip on the trunk's first-parent line, exactly like a fresh
# branch), so the reflog does: a branch that was written on carries a
# `commit:` entry; one that only took the trunk carries `branch: Created from`
# and at most a fast-forward.
#
# A reflog that cannot be read (expired, or never kept) proves nothing, and
# that is not permission: treat the branch as not started and keep it.
not_started() {
  local reflog
  reflog="$(git reflog show "$1" 2>/dev/null || true)"
  if [ -z "$reflog" ]; then
    return 0
  fi
  # No `grep -q`: with `pipefail` its early exit turns into SIGPIPE on the
  # producer side and the whole test reads as false.
  ! printf '%s\n' "$reflog" | grep -F 'commit:' >/dev/null
}

# One detached worktree, named on the command line. It has no branch to
# measure, so the tip comes from the porcelain listing and is checked against
# the trunk: either the tip is an ancestor of the trunk, or its tree appears in
# the trunk's history (the same content landed under another hash, e.g. by
# cherry-pick or squash). Anything else, a missing trunk, or any uncommitted
# file inside is refused with the reason.
remove_detached_worktree() {
  local target="$1" block tip tree seen dirty rc=0
  block="$(git worktree list --porcelain | awk -v p="worktree $target" '$0 == p {on = 1; next} /^worktree / {on = 0} on')"
  if [ -z "$block" ]; then
    echo "worktree として登録されていない: $target" >&2
    return 1
  fi
  if ! printf '%s\n' "$block" | grep -Fx 'detached' >/dev/null; then
    echo "detached HEAD の worktree ではない: $target" >&2
    return 1
  fi
  tip="$(printf '%s\n' "$block" | sed -n 's/^HEAD //p')"
  if [ -z "$tip" ]; then
    echo "tip が読めない: $target" >&2
    return 1
  fi
  if ! git rev-parse --verify --quiet "refs/heads/$trunk" >/dev/null; then
    echo "幹 $trunk が無い" >&2
    return 1
  fi
  git merge-base --is-ancestor "$tip" "refs/heads/$trunk" || rc=$?
  if [ "$rc" = "1" ]; then
    tree="$(git rev-parse "$tip^{tree}")"
    seen="$(git log --format=%T "refs/heads/$trunk" | grep -Fxc "$tree" || true)"
    if [ "${seen:-0}" = "0" ]; then
      echo "tip $tip は幹 $trunk に無い（祖先でも、同じ木でもない）: $target" >&2
      return 1
    fi
  elif [ "$rc" != "0" ]; then
    echo "幹との祖先判定が失敗した（rc=$rc）: $target" >&2
    return 1
  fi
  git worktree repair "$target" >/dev/null 2>&1 || true
  dirty="$(git -C "$target" status --porcelain 2>/dev/null | wc -l)"
  if [ "$dirty" != "0" ]; then
    echo "中に未 commit が $dirty 件 在る: $target" >&2
    return 1
  fi
  echo "  $target  [detached $tip]  幹に含まれる / 未 commit 0 → 外す"
  git worktree remove "$target"
  echo "    外した。戻すなら: git worktree add --detach $target $tip"
}

# One worktree, named on the command line, that the operator has looked at.
#
# The sweep below keeps a worktree with no commits of its own, because a
# builder may be using it. That is right for a sweep and wrong for a relic that
# nobody touches; this route measures and then removes one named worktree.
# For a branch worktree all of these must hold, or it refuses and says which:
# registered, no commit of its own, nothing uncommitted inside, and a tip the
# trunk already contains. A detached worktree is handled by
# `remove_detached_worktree`.
remove_one_worktree() {
  local target="$1" branch ahead dirty
  target="$(cd "$target" 2>/dev/null && pwd || printf '%s' "$target")"
  if [ "$target" = "$root" ]; then
    echo "本体は外せない: $target" >&2
    return 1
  fi
  branch="$(git worktree list | awk -v p="$target" '$1 == p {print}' | sed -n 's/^[^[]*\[\([^]]*\)\].*/\1/p')"
  if [ -z "$branch" ]; then
    remove_detached_worktree "$target"
    return $?
  fi
  if ! not_started "$branch"; then
    echo "その branch は自分の commit を持つ。sweep で判定する: $branch" >&2
    return 1
  fi
  ahead="$(git rev-list --left-right --count "$trunk...$branch" 2>/dev/null | awk '{print $2}')"
  if [ "${ahead:-1}" != "0" ]; then
    echo "幹に無い commit を ${ahead:-?} 件 持つ: $branch" >&2
    return 1
  fi
  # `worktree repair` is a no-op when the links are already right, and fixes
  # the forward link when the directory was moved; without it `status` inside
  # the directory cannot run and the next test could not be trusted.
  git worktree repair "$target" >/dev/null 2>&1 || true
  dirty="$(git -C "$target" status --porcelain 2>/dev/null | wc -l)"
  if [ "$dirty" != "0" ]; then
    echo "中に未 commit が $dirty 件 在る: $target" >&2
    return 1
  fi
  echo "  $target  [$branch]  commit 0 / 未 commit 0 / 幹に含まれる → 外す"
  git worktree remove "$target"
  echo "    外した。戻すなら: git worktree add <path> $branch"
}

if [ -n "${2:-}" ] && [ "${1:-}" = "--remove-worktree" ]; then
  remove_one_worktree "$2"
  exit $?
fi

echo "== worktree =="
# `prune` only forgets entries whose directory has already gone; it never
# deletes a directory, so it is safe to run before looking.
git worktree prune
git worktree list | while read -r path rest; do
  if [ "$path" = "$root" ]; then
    echo "  $path  （本体。触らない）"
    continue
  fi
  # `git worktree list` appends a word after the bracket for a locked or
  # prunable worktree (`[name] locked`). Take only what sits inside the
  # brackets, or `rev-list` exits 128 and `pipefail` + `set -e` kill the loop
  # before the branch section is reached.
  branch="$(printf '%s' "$rest" | sed -n 's/^[^[]*\[\([^]]*\)\].*/\1/p')"
  # A name that still cannot be resolved reads as "?" and is kept, not fatal.
  ahead="$(git rev-list --left-right --count "$trunk...$branch" 2>/dev/null | awk '{print $2}' || true)"
  if [ "${ahead:-1}" = "0" ] && not_started "$branch"; then
    echo "  $path  [$branch]  🔴 commit 0 件（着手前。誰かが使っている）→ 残す"
  elif [ "${ahead:-1}" = "0" ]; then
    echo "  $path  [$branch]  統合済み → 外せる"
    if [ "$remove" = "yes" ]; then git worktree remove "$path" && echo "    外した"; fi
  else
    echo "  $path  [$branch]  🔴 ${ahead:-?} 件 未統合 → 残す"
  fi
done

echo
echo "== branch =="
git for-each-ref --format='%(refname:short)' refs/heads | while read -r branch; do
  if [ "$branch" = "$trunk" ]; then
    echo "  $branch  （幹。触らない）"
    continue
  fi
  counts="$(git rev-list --left-right --count "$trunk...$branch" 2>/dev/null || echo "? ?")"
  ahead="$(printf '%s' "$counts" | awk '{print $2}')"
  behind="$(printf '%s' "$counts" | awk '{print $1}')"
  # A branch that no worktree holds and that the trunk has moved past is a
  # stale marker, not a fresh start: a builder always works inside a worktree,
  # and a fresh branch sits at the trunk, not behind it.
  held="$(git worktree list --porcelain | grep -Fx "branch refs/heads/$branch" || true)"
  if [ "$ahead" = "0" ] && [ -z "$held" ] && [ "$behind" != "0" ] && [ "$behind" != "?" ]; then
    echo "  $branch  古い目印（どの worktree も持たず、幹が $behind 件 先）→ 消せる"
    if [ "$remove" = "yes" ]; then git branch -d "$branch" >/dev/null && echo "    消した"; fi
  elif [ "$ahead" = "0" ] && not_started "$branch"; then
    echo "  $branch  🔴 commit 0 件（着手前。誰かが使っている）→ 残す"
  elif [ "$ahead" = "0" ]; then
    echo "  $branch  統合済み → 消せる"
    # -d refuses an unmerged branch on its own; -D is never used here.
    if [ "$remove" = "yes" ]; then git branch -d "$branch" >/dev/null && echo "    消した"; fi
  else
    echo "  $branch  🔴 $ahead 件 未統合 → 残す（$trunk へ入れてから）"
  fi
done

echo
if [ "$remove" = "no" ]; then
  echo "見ただけ。消すなら: scripts/tidy-branches.sh --remove"
fi
