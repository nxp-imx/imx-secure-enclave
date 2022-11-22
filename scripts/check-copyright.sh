#!/bin/bash

# Check-copyright script
# Check file NXP copyright and date

set -u

if tty --quiet <&2 ; then
    W="$(tput bold)$(tput setaf 1)WARNING$(tput sgr0)"
else
    W="WARNING"
fi

: "${CHECK_STYLE_IGNORE:=.check-style.ignore}"
: "${FILE_EXT:=c|h|cpp|in}"

ret_error=0

function usage() {
  local myscript

  myscript=$(basename "$0")
  echo "Usage: $myscript [--working]                 Check working area"
  echo "       $myscript <commit>                    Check specific commit"
  echo "       $myscript --diff <commit1> <commit2>  Check diff commit1...commit2"
  echo "       $myscript --cached                    Check staging area"
  echo "       $myscript --help                      This help"
  exit 1
}

function is_ignored() {
  while read -r ignore_pattern ; do
    case $f in
      $ignore_pattern)
          return 0
          ;;
    esac
  done < <(grep -Ev '^[[:blank:]]*(#|$)' "${CHECK_STYLE_IGNORE}")

  return 1
}

function _copyright() {
  for f in $1 ; do
    if is_ignored "${f}" ; then
      continue
    fi

    if [[ ! -e ${f} ]]; then
      echo "WARNING: File $f deleted"
      continue
    fi

    # Search copyright in 20 first lines, with current year date
    head -n 20 "$f" | grep "[Cc]opyright 20..* NXP" | \
          grep "$(date +%Y)" > /dev/null
    if [[ $? -ne 0 ]]; then
      echo "$W: $f misses correct copyright info." >&2
      ret_error=1
    fi
  done
}

function checkworking() {
  files=$(git diff --name-only --diff-filter=ACMR -- . | \
          grep -E "\.(${FILE_EXT})$")
  _copyright "$files"
}

function checkstaging() {
  files=$(git diff --cached --name-only --diff-filter=ACMR | \
          grep -E "\.(${FILE_EXT})$")
  _copyright "$files"
}

function checkcommit() {
  files=$(git diff-tree --no-commit-id --name-only --diff-filter=ACMR -r "$1" | \
          grep -E "\.(${FILE_EXT})$")
  _copyright "$files"
}

function checkdiff() {
  commits=$(git rev-list "$1..$2")
  if [[ ${#commits} -eq 0 ]]; then
    echo "ERROR: Not commits to scan"
    exit 1
  fi

  for c in ${commits[@]}
  do
    echo ""
    echo "========================================================"
    echo " commit $c "
    checkcommit "$c"
    echo "========================================================"
  done
}

opt_action="${1:---working}"

case "${opt_action}" in
  --cached)
    echo "Check staging area"
    checkstaging
    ;;

  --diff)
    echo "Check diff ($2 $3)"
    checkdiff "$2" "$3"
    ;;

  --working)
    echo "Check working area"
    checkworking
    ;;

  --help|-h)
    usage
    ;;

  *)
    echo "Check commit $1"
    checkcommit "$1"
    ;;
esac

if [[ ${ret_error} -eq 1 ]]; then
  (
    echo ""
    echo "Wrong Copyrights detected in some files."
    echo "The copyright notice should look like:"
    echo ""
    echo "   /*"
    echo "    * Copyright $(date +%Y) NXP"
    echo "    */"
    echo ""
    echo "Refer to https://confluence.sw.nxp.com/display/OSS/File+Header for details"
    echo ""
  ) >&2
fi

exit ${ret_error}
