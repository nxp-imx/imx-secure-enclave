#!/bin/bash

# ClangFormat script
# Install ClangFormat in tmp directory

set -eu

# ClangFormat HTTP site
CLANGFORMAT_HTTP="https://github.com/llvm/llvm-project/releases/download"
GIT_CLANGFORMAT="${GIT_CLANGFORMAT:-git-clang-format}"
CLANGFORMAT_VERSION="${CLANGFORMAT_VERSION:-"10.0.0"}"

# git-clang-format check options
EXTENSIONS="c,c.in,h,h.in,cpp"
STYLE="file"

# Get the Git Top level directory
function get_toplevel()
{
  local topdir
  topdir=$(git rev-parse --show-toplevel)
  echo "$topdir"
}

# Install clang-format version in the given directory
function install_clang()
{
  local instdir="$1"
  local archive="clang+llvm-${CLANGFORMAT_VERSION}-x86_64-linux-gnu-ubuntu-18.04.tar.xz"
  local folder="clang+llvm-${CLANGFORMAT_VERSION}-x86_64-linux-gnu-ubuntu-18.04"
  local path="${instdir}/${folder}"

  mkdir -p "${instdir}"
  archive="${instdir}/${archive}"

  if [[ ! -d "${path}" ]]; then
    if [[ ! -f "${archive}" ]]; then
        wget -N "${CLANGFORMAT_HTTP}/llvmorg-${CLANGFORMAT_VERSION}/${archive} -P ${instdir}"
    fi

    tar xvf "${archive}" -C "${instdir}"
  fi

  if [[ ! -f "${path}/bin/git-clang-format" ]]; then
    echo "Error: git-clang-format not found in ${path}/bin"
    exit 1
  fi

  GIT_CLANGFORMAT="${path}/bin/git-clang-format"
}

function _ex_checkformat()
{
  local cmd="${GIT_CLANGFORMAT}"

  if [[ $# -gt 0 ]]; then
    cmd="${cmd} $1"
  fi

  cmd="${cmd} --style=${STYLE} --extensions ${EXTENSIONS} --quiet --diff -v"
  res=$(eval ${cmd})

  error=$(echo "${res}" | \
        grep -E -v "(no modified files to format|clang-format did not modify any files)")

  echo "${error}"
}

function check_staged()
{
  echo "Checking git staged area:  "
  res=$(_ex_checkformat '')

  if [[ -z "${res}" ]]; then exit 0; fi

  echo "${res}"

  exit 1
}

function check_commits()
{
  local err=0;
  git_head=$(git rev-parse HEAD)

  commits=("$@")
  nb_max=${#commits[@]}

  echo "Checking commit(s): ${nb_max}"

  i=${nb_max}
  i=$((i-1))

  while [[ $i -ge 0 ]]
  do
    if [[ ${git_head} == ${commits[$i]} ]]; then break; fi

    if [[ $i -gt 0 ]]; then
      c=${commits[$i-1]}
      res=$(_ex_checkformat "${commits[$i]} ${c}")
    else
      c=${commits[$i]}
      res=$(_ex_checkformat "${c}")
    fi

    printf "\n========================================================\n"
    printf " Commit ${c}\n\n"
    if [[ -n "${res}" ]]; then
      echo "${res}"
      err=1
    fi
    printf "\n========================================================\n"

    i=$((i-1))
  done

  exit "${err}"
}

function usage() {
  local myscript

  myscript=$(basename "$0")
  echo "Usage: $myscript [--staged]    Check git staged area (default)"
  echo "       $myscript [--install]   Install clang-format in .tmp directory"
  echo "       $myscript <commit>      Check specific commit(s)"
  echo "       $myscript --help        This help"
  exit 1
}

# Get the git root directory
GIT_TOPLEVEL=$(get_toplevel)

# Install checkpatch if not present
if [[ ! -x $(command -v "${GIT_CLANGFORMAT}") ]]; then
  install_clang "$GIT_TOPLEVEL"/.tmp
fi

op=${1:---staged}
case "$op" in
  --staged)
    check_staged
    ;;

  --help|-h)
    usage
    ;;

  --install)
    ;;

  *)
    check_commits $@
    ;;
esac
