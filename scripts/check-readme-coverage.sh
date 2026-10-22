#!/usr/bin/env bash
# Check that README.ja.md and README.md each list every stage of
# docs/design.md in their capability table.
#
# Usage:
#   ./scripts/check-readme-coverage.sh [--root <dir>]
#
#   --root <dir>  check the tree at <dir> instead of the one this script
#                 lives in
#
# The stages come from the two stage tables of docs/design.md: the rows that
# start with `| **N. `. The row `1w` belongs to stage 1 and is not a stage of
# its own. The numbers must run 1..N without a gap, so an extraction that
# silently misses a row stops the check instead of shrinking it.
#
# Each README is read only inside its capability section, the section whose
# heading starts with the prefix in README_SECTIONS. A stage is covered when
# that section holds a table row `| N <name> | <text> | ...` with a non-empty
# second cell. A row of the same shape in another section (`| 1 <sentence> |`)
# does not count.
#
# Exit status: 0 = every stage is covered in both READMEs, 1 = a stage is
# missing, a table has no rows, no stage could be read from the design, or a
# file cannot be read, 2 = bad arguments.
#
# Do not loosen this script to make a run pass. A check that passes everything
# is not a check.

set -euo pipefail

usage() {
  sed -n '2,27p' "$0"
}

# "<file>|<prefix of the heading that opens the capability section>"
README_SECTIONS=(
  "README.ja.md|## できること"
  "README.md|## What it can do"
)

# Print "<number><TAB><name>" for each stage of the design, first row wins.
design_stages() {
  awk -F'|' '
    /^\| \*\*[0-9]+\. / {
      cell = $2
      sub(/^ *\*\*/, "", cell)
      sub(/ *\*\* *$/, "", cell)
      number = cell
      sub(/\..*/, "", number)
      name = cell
      sub(/^[0-9]+\. */, "", name)
      if (!(number in seen)) {
        seen[number] = 1
        print number "\t" name
      }
    }' "$1"
}

# Exit 0 when the first column of stdin is 1, 2, 3, ... in order.
numbers_are_contiguous() {
  awk -F'\t' '$1 != NR { bad = 1 } END { exit bad }'
}

# Print the stage number of each filled table row inside the capability
# section of <file>, whose heading starts with <prefix>.
readme_stage_numbers() {
  awk -v prefix="$2" '
    index($0, prefix) == 1 { inside = 1; next }
    /^## / { inside = 0 }
    inside && /^\| [0-9]+ / {
      cells = split($0, cell, "|")
      if (cells >= 4 && cell[3] ~ /[^ ]/) {
        split(cell[2], word, " ")
        print word[1]
      }
    }' "$1"
}

# Check one README against the stages. Prints the verdict, returns 1 on a miss.
check_readme() {
  local stages=$1 file=$2 prefix=$3
  local covered rows total=0 found=0 missing="" number name
  if [ ! -r "$file" ]; then
    echo "NG $file を読めない"
    return 1
  fi
  covered=$(readme_stage_numbers "$file" "$prefix")
  rows=$(printf '%s\n' "$covered" | awk 'NF { n++ } END { print n + 0 }')
  while IFS=$'\t' read -r number name; do
    total=$((total + 1))
    case $'\n'"$covered"$'\n' in
      *$'\n'"$number"$'\n'*) found=$((found + 1)) ;;
      *) missing+="${missing:+, }${number} ${name}" ;;
    esac
  done <<< "$stages"
  echo "$file: 「${prefix}」の節の表に ${rows} 行。設計の ${total} 段のうち ${found} 段が載っている"
  if [ "$rows" -eq 0 ]; then
    echo "NG $file: 「${prefix}」の節か、その表が無い（行が 0）"
    return 1
  fi
  if [ -n "$missing" ]; then
    echo "NG $file に載っていない段: $missing"
    return 1
  fi
  echo "OK $file は設計の全段を載せている"
}

root=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root)
      [ $# -ge 2 ] || { usage; exit 2; }
      root="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

if [ -n "$root" ]; then
  cd "$root" || exit 1
else
  cd "$(dirname "$0")/.." || exit 1
fi

design=docs/design.md
if [ ! -r "$design" ]; then
  echo "NG $design を読めない"
  exit 1
fi
stages=$(design_stages "$design")
count=$(printf '%s\n' "$stages" | awk 'NF { n++ } END { print n + 0 }')
echo "設計の段: $design から ${count} 段を抜いた"
if [ "$count" -eq 0 ]; then
  echo "NG 設計の表から 0 段しか抜けていない。式が合っていない。以降の OK は無意味"
  exit 1
fi
if ! printf '%s\n' "$stages" | numbers_are_contiguous; then
  echo "NG 設計の段の番号が 1 から欠けなく並んでいない。抜き漏らしの疑い"
  printf '%s\n' "$stages"
  exit 1
fi
printf '%s\n' "$stages" | sed 's/^/  /'

fail=0
for entry in "${README_SECTIONS[@]}"; do
  check_readme "$stages" "${entry%%|*}" "${entry#*|}" || fail=1
done

echo "---"
if [ "$fail" -eq 0 ]; then
  echo "通過。README は設計の全段を載せている"
else
  echo "止まれ。上の NG を潰す"
fi
exit "$fail"
