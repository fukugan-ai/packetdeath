#!/usr/bin/env bash
# Run before every commit (tree checks) and before every push (--history).
# Counts personal environment information in the working tree and, with
# --history, in the authors, committers and messages of a revision.
#
# Usage:
#   ./scripts/check-privacy.sh [--root <dir>] [--patterns <file>] [--generic-only]
#                              [--history [<rev>]]
#
#   --root <dir>       check the repository at <dir> instead of the one this
#                      script lives in
#   --patterns <file>  local list of personal literals, one extended regular
#                      expression per line, '#' starts a comment. The default is
#                      ${XDG_CONFIG_HOME:-$HOME/.config}/packetdeath/privacy-patterns.txt
#                      The file stays outside the repository: a literal host
#                      name or nickname written in a tracked file is itself a
#                      leak, so no personal literal is written in this script.
#   --generic-only     skip the local list. Only the generic patterns and the
#                      names this machine reports for itself are checked.
#   --history [<rev>]  also check the commit authors, committers and messages
#                      of <rev> (default HEAD). Every author and committer
#                      address must be a GitHub noreply address.
#
# Exit status: 0 = pass, 1 = stop, 2 = bad arguments.
#
# Do not loosen this script to make a run pass. A check that passes everything
# is not a check.
#
# Do not drop `--untracked`. Without it only tracked files are read, a file
# that was written but not yet committed is never scanned, and "0 hits" is a
# false negative. `--untracked` does not read files that .gitignore excludes,
# which is the wanted behaviour.

set -uo pipefail

usage() {
  sed -n '2,29p' "$0"
}

root_override=""
patterns_file=""
generic_only=no
history=no
history_rev="HEAD"
while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || { usage; exit 2; }
      root_override="$2"; shift 2 ;;
    --patterns)
      [ $# -ge 2 ] || { usage; exit 2; }
      patterns_file="$2"; shift 2 ;;
    --generic-only) generic_only=yes; shift ;;
    --history)
      history=yes; shift
      if [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; then history_rev="$1"; shift; fi ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -n "$root_override" ]; then
  cd "$root_override" || exit 1
else
  cd "$(dirname "$0")/.." || exit 1
fi

fail=0
SELF='^scripts/check-privacy\.sh:'

# Join the non-empty, non-comment lines on stdin into one alternation.
join_alternation() {
  grep -vE '^[[:space:]]*(#|$)' | paste -sd'|' -
}

# Escape one literal for use inside an extended regular expression.
escape_ere() {
  sed 's/[][\\.*^$+?(){}|]/\\&/g'
}

# Names this machine reports for itself: user, host name, non-loopback
# addresses. They are read at run time, so no literal is stored here.
# Tokens shorter than four characters and common generic names are dropped
# because they match inside ordinary words.
derived_tokens() {
  {
    id -un 2>/dev/null
    hostname 2>/dev/null
    hostname -I 2>/dev/null | tr ' ' '\n'
  } | awk 'length($0) >= 4' | grep -vxE 'root|localhost|ubuntu|debian|runner|docker|admin|user' | sort -u
}

# 1. Generic patterns. `/home/` is limited to the users that exist on this
#    machine: a wide `/home/[a-z0-9_-]+/` also hits dummy paths in tests, and a
#    check that raises false alarms is switched off or ignored.
HOME_USERS=$(ls -1 /home 2>/dev/null | grep -E '^[a-z0-9_.-]+$' | tr '\n' '|' | sed 's/|$//')
[ -z "$HOME_USERS" ] && HOME_USERS='[a-z0-9_-]+'
GENERIC_PAT="/home/(${HOME_USERS})/|/mnt/[a-z]/Users/|[A-Za-z]:\\\\Users\\\\|Chrome SxS"

# 2. Derived tokens, each wrapped so that `name-suffix` is not a hit for `name`.
DERIVED_PAT=""
derived_list=$(derived_tokens)
if [ -n "$derived_list" ]; then
  DERIVED_PAT=$(printf '%s\n' "$derived_list" | escape_ere \
    | sed 's/.*/(^|[^A-Za-z0-9_.-])&($|[^A-Za-z0-9_-])/' | paste -sd'|' -)
fi

# 3. Local list of personal literals.
LOCAL_PAT=""
pattern_source="(none)"
if [ "$generic_only" = no ]; then
  default_file="${XDG_CONFIG_HOME:-${HOME:-}/.config}/packetdeath/privacy-patterns.txt"
  pattern_source="${patterns_file:-$default_file}"
  if [ -r "$pattern_source" ]; then
    LOCAL_PAT=$(join_alternation < "$pattern_source")
  fi
fi

ALL_PAT="$GENERIC_PAT"
[ -n "$DERIVED_PAT" ] && ALL_PAT="$ALL_PAT|$DERIVED_PAT"
[ -n "$LOCAL_PAT" ] && ALL_PAT="$ALL_PAT|$LOCAL_PAT"

# E-mail addresses. Allowed: GitHub noreply addresses, the model attribution
# trailer, reserved example names and localhost.
EMAIL_RE='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'
EMAIL_OK='(@users\.noreply\.github\.com|noreply@anthropic\.com|@example\.(com|org|net)|@localhost)$'

echo "=== 0. 陰性対照（先に打つ。当たらないなら以降の OK を信用するな）==="
# (a) a word that must be present is found, so the scan range is sane
probe_all=$(git grep --untracked -I -l -E 'packetdeath' -- . 2>/dev/null | wc -l)
# (b) at least one hit comes from an untracked file when untracked files exist
untracked_files=$(git ls-files --others --exclude-standard | wc -l)
probe_untracked=0
if [ "$untracked_files" -gt 0 ]; then
  # `comm` is not used: it wants sorted input and warns under another locale,
  # and a check that makes noise teaches the reader to skip real warnings.
  # `grep -Fxv -f` subtracts whole lines and does not depend on the order.
  # Any character will do here: a new file need not contain the project name.
  probe_untracked=$(git grep --untracked -I -l -E '.' -- . 2>/dev/null \
    | grep -Fxv -f <(git grep -I -l -E '.' -- . 2>/dev/null) | wc -l)
fi
echo "必ず在る語が当たった file 数: $probe_all"
echo "working tree の untracked file 数: $untracked_files"
echo "うち --untracked でだけ拾えた file 数: $probe_untracked"
if [ "$probe_all" -eq 0 ]; then
  echo "NG 検知器が壊れている。必ず在る語が0件。以降の OK は無意味"
  fail=1
elif [ "$untracked_files" -gt 0 ] && [ "$probe_untracked" -eq 0 ]; then
  echo "NG untracked file が在るのに1つも拾えていない。走査範囲が tracked に閉じている疑い"
  fail=1
else
  echo "OK 走査範囲は untracked を含む"
fi

# (c) the combined pattern is a valid expression (grep exits 2 when it is not)
printf '' | grep -qE -- "$ALL_PAT"
if [ $? -gt 1 ]; then
  echo "NG pattern が正規表現として壊れている。以降の OK は無意味"
  fail=1
else
  echo "OK pattern は正規表現として読める"
fi

# (d) the pattern finds the user of this machine, and not a dummy path
me="/home/$(id -un)/somewhere"
if [ -d "/home/$(id -un)" ]; then
  if printf '%s\n' "$me" | grep -qE -- "$ALL_PAT"; then
    echo "OK pattern は実在利用者の path を拾う（$me）"
  else
    echo "NG pattern が実在利用者の path を拾えない（$me）。絞り込みすぎ。以降の OK は無意味"
    fail=1
  fi
fi
if [ "$(id -un)" != "x" ] && printf '%s\n' "/home/x/.config/app" | grep -qE -- "$GENERIC_PAT"; then
  echo "NG pattern が test 用ダミー /home/x/ を拾う。偽陽性が出る"
  fail=1
else
  echo "OK pattern は test 用ダミーを拾わない"
fi

# (e) every derived token is found by its own wrapped pattern
if [ -n "$derived_list" ]; then
  miss=0
  while IFS= read -r token; do
    if ! printf 'x %s y\n' "$token" | grep -qE -- "$DERIVED_PAT"; then
      echo "NG この機械の名前 '$token' を pattern が拾えない"
      miss=1
    fi
  done <<< "$derived_list"
  if [ "$miss" -eq 0 ]; then
    echo "OK この機械の user / host / address を pattern が拾う（$(printf '%s\n' "$derived_list" | wc -l) 個）"
  else
    fail=1
  fi
fi

# (f) the local list is present and not empty, unless it was skipped on purpose
if [ "$generic_only" = yes ]; then
  echo "警告 --generic-only: 個人の固有名（host 名、あだ名、LAN の address など）は検査していない"
elif [ -z "$LOCAL_PAT" ]; then
  echo "NG 個人情報の pattern file が無いか空（$pattern_source）。個人の固有名を検査できない"
  echo "   作るか --patterns <file> で渡す。固有名を見ない検査だけでよければ --generic-only"
  fail=1
else
  echo "OK 個人情報の pattern file を読んだ（$pattern_source。$(grep -cvE '^[[:space:]]*(#|$)' "$pattern_source") 行）"
fi

# (g) the e-mail filter keeps a personal address and drops a noreply address
if printf 'a@gmail.com\n' | grep -oE -- "$EMAIL_RE" | grep -qvE -- "$EMAIL_OK" \
  && ! printf 'a@users.noreply.github.com\n' | grep -oE -- "$EMAIL_RE" | grep -qvE -- "$EMAIL_OK"; then
  echo "OK e-mail の検査は個人の address を拾い、noreply を拾わない"
else
  echo "NG e-mail の検査が陽性対照か陰性対照を外した。以降の OK は無意味"
  fail=1
fi

echo "=== 1. 個人環境情報（path、この機械の名前、個人の固有名。file 名を含む）==="
hits=$(git grep --untracked -I -n -E -e "$ALL_PAT" -- . 2>/dev/null | grep -v "$SELF" || true)
name_hits=$( { git ls-files; git ls-files --others --exclude-standard; } | grep -E -- "$ALL_PAT" || true)
if [ -n "$hits$name_hits" ]; then
  [ -n "$hits" ] && echo "$hits"
  [ -n "$name_hits" ] && printf 'file 名: %s\n' "$name_hits"
  echo "NG $(printf '%s\n%s\n' "$hits" "$name_hits" | grep -c .) 件"
  fail=1
else
  echo "OK 0 件"
fi

echo "=== 1b. e-mail address（noreply と例示用を除く）==="
emails=$(git grep --untracked -I -n -o -E -e "$EMAIL_RE" -- . 2>/dev/null \
  | grep -vE -- "$EMAIL_OK" | grep -v "$SELF" || true)
if [ -n "$emails" ]; then
  echo "$emails"
  echo "NG $(printf '%s\n' "$emails" | wc -l) 件"
  fail=1
else
  echo "OK 0 件"
fi

echo "=== 2. 秘密鍵と証明書（tracked と untracked の両方）==="
keys=$( { git ls-files; git ls-files --others --exclude-standard; } \
  | grep -E '\.(pem|key|crt|der|p12|pfx)$' || true)
if [ -n "$keys" ]; then
  echo "$keys"
  echo "NG 鍵・証明書が working tree に在る（.gitignore で塞いでいても、置き場を repo の外へ移す）"
  fail=1
else
  echo "OK 0 件"
fi

echo "=== 3. 鍵の中身が本文へ貼られていないか ==="
inline=$(git grep --untracked -I -n -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' -- . 2>/dev/null \
  | grep -v "$SELF" || true)
if [ -n "$inline" ]; then
  echo "$inline"
  echo "NG 秘密鍵が本文へ貼られている"
  fail=1
else
  echo "OK 0 件"
fi

echo "=== 4. 文書と code の comment に、利用者の言葉の引用と出所の印が無いか ==="
# Design documents, runbooks and code comments carry no quotation and no
# provenance mark of the form "<who> <date>". The mark belongs to private
# notes only.
QUOTE_PAT='利用者([[:space:]]|　)?20[0-9]{2}-[0-9]{2}-[0-9]{2}'
if printf '%s\n' '利用者 2026-10-03「x」' | grep -qE -- "$QUOTE_PAT"; then
  echo "OK pattern は出所の印を拾う"
else
  echo "NG pattern が出所の印を拾えない。以降の OK は無意味"
  fail=1
fi
quotes=$(git grep --untracked -I -n -E -e "$QUOTE_PAT" -- 'docs/*.md' 'README*.md' 'src/*.rs' 'tests/*.rs' 2>/dev/null \
  | grep -v "$SELF" || true)
if [ -n "$quotes" ]; then
  echo "$quotes"
  echo "NG $(printf '%s\n' "$quotes" | wc -l) 件（引用と出所の印は公開する file に置かない）"
  fail=1
else
  echo "OK 0 件"
fi

echo "=== 5. code の comment に、日付と指摘の印が無いか ==="
# A code comment says what the code does. Dates, reviewer notes and ordering
# marks do not belong in it. Only comment lines are read ('//', '///', '//!',
# and '#' in .ps1 and the blocklists); a date inside a string literal is not a
# comment and is not a hit.
MARK_PAT='^[[:space:]]*(//|#).*(20[0-9]{2}-[0-9]{2}-[0-9]{2}|reviewer|検証者|発注|利用者の逐語)'
if printf '%s\n' '    // reviewer 指摘、2026-09-11 High' | grep -qE -- "$MARK_PAT"; then
  echo "OK pattern は指摘の印を拾う"
else
  echo "NG pattern が指摘の印を拾えない。以降の OK は無意味"
  fail=1
fi
if printf '%s\n' '    let s = "ts\":\"2026-01-01T00:00:00Z";' | grep -qE -- "$MARK_PAT"; then
  echo "NG pattern が文字列の中の日付を拾う。偽陽性が出る"
  fail=1
else
  echo "OK 文字列の中の日付を拾わない"
fi
marks=$(git grep --untracked -I -n -E -e "$MARK_PAT" -- 'src/*.rs' 'src/*.ps1' 'tests/*.rs' 'tests/*.ps1' 'blocklists/*.txt' 2>/dev/null \
  | grep -v "$SELF" || true)
if [ -n "$marks" ]; then
  echo "$marks"
  echo "NG $(printf '%s\n' "$marks" | wc -l) 件（経緯は公開する file に置かない）"
  fail=1
else
  echo "OK 0 件"
fi

echo "=== 6. 履歴の author / committer / 件名と本文（--history）==="
if [ "$history" = no ]; then
  echo "skip --history を付けたときだけ検査する（push の前に打つ）"
else
  if ! git rev-parse --verify -q "${history_rev}^{commit}" >/dev/null; then
    echo "NG revision '$history_rev' を読めない"
    fail=1
  else
    commits=$(git rev-list --count "$history_rev")
    who=$(git log --format='%an <%ae>%n%cn <%ce>' "$history_rev" | sort -u)
    echo "対象: $history_rev（$commits commit。author と committer の組 $(printf '%s\n' "$who" | wc -l) 通り）"
    # control: a personal address is not a noreply address
    if printf 'x <a@gmail.com>\n' | grep -qvE '<[^<>]*@users\.noreply\.github\.com>$'; then
      echo "OK 陽性対照: 個人の address は noreply として通らない"
    else
      echo "NG 陽性対照が外れた。以降の OK は無意味"
      fail=1
    fi
    not_noreply=$(printf '%s\n' "$who" | grep -vE '<[^<>]*@users\.noreply\.github\.com>$' || true)
    personal_who=$(printf '%s\n' "$who" | grep -E -- "$ALL_PAT" || true)
    if [ -n "$not_noreply" ] || [ -n "$personal_who" ]; then
      [ -n "$not_noreply" ] && printf 'noreply でない author / committer:\n%s\n' "$not_noreply"
      [ -n "$personal_who" ] && printf '個人情報に当たる author / committer:\n%s\n' "$personal_who"
      echo "NG author / committer が noreply でないか、個人情報に当たる"
      fail=1
    else
      echo "OK author / committer は noreply だけで、個人情報に当たらない"
    fi
    msg_hits=$(git log --format='commit %h%n%B' "$history_rev" | grep -n -E -- "$ALL_PAT" || true)
    msg_mail=$(git log --format='%B' "$history_rev" | grep -oE -- "$EMAIL_RE" | grep -vE -- "$EMAIL_OK" || true)
    if [ -n "$msg_hits$msg_mail" ]; then
      printf '%s\n%s\n' "$msg_hits" "$msg_mail" | grep .
      echo "NG commit message が個人情報に当たる"
      fail=1
    else
      echo "OK commit message は個人情報に当たらない"
    fi
  fi
fi

echo "---"
if [ "$fail" -eq 0 ]; then
  echo "通過。commit してよい"
else
  echo "止まれ。上の NG を潰してから commit する"
fi
exit "$fail"
