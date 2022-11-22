#!/bin/bash

# Checkpatch script
# Install checkpatch in tmp directory

set -eu

# Checkpatch HTTP site
CHECKPATCH_HTTP="https://raw.githubusercontent.com/torvalds/linux/master/scripts"
CHECKPATCH="${CHECKPATCH:-checkpatch.pl}"

# Get the Git Top level directory
function get_toplevel() {
  local topdir
  topdir=$(git rev-parse --show-toplevel)
  echo "$topdir"
}

# Install checkpatch linux tool and spelling
function install_checkpatch() {
  local instdir=$1

  mkdir -p "$instdir"

  if ! [ -f "$instdir"checkpatch.pl ]; then
    wget -N "$CHECKPATCH_HTTP"/checkpatch.pl -P "$instdir"
    wget -N "$CHECKPATCH_HTTP"/spelling.txt -P "$instdir"
  fi

  # Ensure checkpatch.pl is executable
  chmod a+x "$instdir"checkpatch.pl

  echo "$instdir"checkpatch.pl
}

function const_structs_check() {
  local checkpatch_dir

  checkpatch_dir=$(dirname "$CHECKPATCH")

  if ! [ -f "$checkpatch_dir"/const_structs.checkpatch ]; then
    echo "invalid.struct.name" > \
      "$checkpatch_dir"/const_structs.checkpatch
  fi
}

# Checkpatch ignore file/path defined in the .checkpatch.ignore
function checkpatch_ignore() {
  _CP_EXCLED=()

  if [ -f "$GIT_TOPLEVEL"/.checkpatch.ignore ]; then
    while IFS= read -r excl_file
    do
      _CP_EXCLED+=(":(exclude)$excl_file")
    done < "$GIT_TOPLEVEL"/.checkpatch.ignore
  fi
}

function _ex_checkpatch() {
  local typedefs_opt=""

  # Use --typedefsfile if supported by the checkpatch tool
  # and if typedefs.checkpatch is present at Git Top Level
  if [ -f "$GIT_TOPLEVEL"/typedefs.checkpatch ]; then
    typedefs_opt="--typedefsfile typedefs.checkpatch"
  fi

  $CHECKPATCH --help 2>&1 | grep -q -- --typedefsfile || \
      typedefs_opt="";

  # Ignore NOT_UNIFIED_DIFF in case patch has no diff
  # (e.g., all paths filtered out)
  $CHECKPATCH --quiet --ignore FILE_PATH_CHANGES \
      --ignore GERRIT_CHANGE_ID \
      --ignore NOT_UNIFIED_DIFF \
      --ignore CAMELCASE \
      --ignore PREFER_KERNEL_TYPES \
      --ignore CONCATENATED_STRING \
      --no-tree \
      --strict \
      $typedefs_opt \
      -
}

function checkpatch() {
  git show --oneline --no-patch "$1"
  # The first git 'format-patch' shows the commit message
  # The second one produces the diff
  (git format-patch "$1"^.."$1" --stdout | sed -n '/^diff --git/q;p'; \
   git format-patch "$1"^.."$1" --stdout -- . ${_CP_EXCLED[*]} | \
    sed -n '/^diff --git/,$p') | _ex_checkpatch
}

function checkstaging() {
  git diff --cached -- . ${_CP_EXCLED[*]} | _ex_checkpatch
}

function checkworking() {
  git diff -- . ${_CP_EXCLED[*]} | _ex_checkpatch
}

function checkdiff() {
  git diff "$1"..."$2" -- . ${_CP_EXCLED[*]} | _ex_checkpatch
}

function usage() {
  local myscript

  myscript=$(basename "$0")
  echo "Usage: $myscript [--working]                 Check working area"
  echo "       $myscript <commit>...                 Check specific commit(s)"
  echo "       $myscript --diff <commit1> <commit2>  Check diff commit1...commit2"
  echo "       $myscript --cached                    Check staging area"
  echo "       $myscript --help                      This help"
  exit 1
}

# Get the git root directory
GIT_TOPLEVEL=$(get_toplevel)

# Install checkpatch if not present
if [[ ! -x $(command -v "${CHECKPATCH}") ]]; then
  CHECKPATCH=$(install_checkpatch "$GIT_TOPLEVEL"/.tmp/)
fi

const_structs_check
checkpatch_ignore

cd "$GIT_TOPLEVEL"

op=${1:---working}
case "$op" in
  --cached)
    echo "Checking staging area:  "
    checkstaging
    ;;
  --diff)
    echo "Checking diff (diff $1...$2)"
    checkdiff "$2" "$3"
    ;;
  --working)
    echo "Checking working area:  "
    checkworking
    ;;
  --help|-h)
    usage
    ;;
  --install)
    ;;
  *)
    echo "Checking commit(s):"
    for c in "$@"; do checkpatch "$c"; done
    ;;
esac
