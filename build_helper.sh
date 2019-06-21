#!/bin/bash -eu

# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.


# This is a helpful script to build MVFST in the supplied dir
# It pulls in dependencies such as folly and fizz in the _build/deps dir.

# Useful constants
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_OFF="\033[0m"

usage() {
cat 1>&2 <<EOF

Usage ${0##*/} [-h|?] [-p PATH] [-i INSTALL_PREFIX]
  -p BUILD_DIR                           (optional): Path of the base dir for mvfst
  -i INSTALL_PREFIX                      (optional): install prefix path
  -m                                     (optional): Build folly without jemalloc
  -h|?                                               Show this help message
EOF
}

while getopts ":hp:i:m" arg; do
  case $arg in
    p)
      BUILD_DIR="${OPTARG}"
      ;;
    i)
      INSTALL_PREFIX="${OPTARG}"
      ;;
    m)
      MVFST_FOLLY_USE_JEMALLOC="n"
      ;;
    h | *) # Display help.
      usage
      exit 0
      ;;
  esac
done

# Validate required parameters
if [ -z "${BUILD_DIR-}" ] ; then
  echo -e "${COLOR_RED}[ INFO ] Build dir is not set. So going to build into _build ${COLOR_OFF}"
  BUILD_DIR=_build
  mkdir -p $BUILD_DIR
fi

if [[ -n "${MVFST_FOLLY_USE_JEMALLOC-}" ]]; then
    if [[ "$MVFST_FOLLY_USE_JEMALLOC" != "n" ]]; then
        unset $MVFST_FOLLY_USE_JEMALLOC
    fi
fi

### configure necessary build and install directories

cd $BUILD_DIR || exit
BWD=$(pwd)
DEPS_DIR=$BWD/deps
mkdir -p "$DEPS_DIR"

MVFST_BUILD_DIR=$BWD/build
mkdir -p "$MVFST_BUILD_DIR"

if [ -z "${INSTALL_PREFIX-}" ]; then
  FOLLY_INSTALL_DIR=$DEPS_DIR
  FIZZ_INSTALL_DIR=$DEPS_DIR
  MVFST_INSTALL_DIR=$BWD
else
  FOLLY_INSTALL_DIR=$INSTALL_PREFIX
  FIZZ_INSTALL_DIR=$INSTALL_PREFIX
  MVFST_INSTALL_DIR=$INSTALL_PREFIX
fi

# Default to parallel build width of 4.
# If we have "nproc", use that to get a better value.
# If not, then intentionally go a bit conservative and
# just use the default of 4 (e.g., some desktop/laptop OSs
# have a tendency to freeze if we actually use all cores).
set +x
nproc=4
if [ -z "$(hash nproc 2>&1)" ]; then
    nproc=$(nproc)
fi
set -x

function install_dependencies_linux() {
  sudo apt-get install        \
    g++                       \
    cmake                     \
    libboost-all-dev          \
    libevent-dev              \
    libdouble-conversion-dev  \
    libgoogle-glog-dev        \
    libgflags-dev             \
    libiberty-dev             \
    liblz4-dev                \
    liblzma-dev               \
    libsnappy-dev             \
    make                      \
    zlib1g-dev                \
    binutils-dev              \
    libjemalloc-dev           \
    libssl-dev                \
    pkg-config                \
    libsodium-dev
}

function install_dependencies_mac() {
  # install the default dependencies from homebrew
  brew install               \
    cmake                    \
    boost                    \
    double-conversion        \
    gflags                   \
    glog                     \
    libevent                 \
    lz4                      \
    snappy                   \
    xz                       \
    openssl                  \
    libsodium

  brew link                 \
    boost                   \
    double-conversion       \
    gflags                  \
    glog                    \
    libevent                \
    lz4                     \
    snappy                  \
    xz                      \
    libsodium
}

function setup_folly() {
  FOLLY_DIR=$DEPS_DIR/folly
  FOLLY_BUILD_DIR=$DEPS_DIR/folly/build/

  if [ ! -d "$FOLLY_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning folly repo ${COLOR_OFF}"
    git clone https://github.com/facebook/folly.git "$FOLLY_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] install dependencies ${COLOR_OFF}"
    if [ "$Platform" = "Linux" ]; then
      install_dependencies_linux
    elif [ "$Platform" = "Mac" ]; then
        install_dependencies_mac
    else
      echo -e "${COLOR_RED}[ ERROR ] Unknown platform: $Platform ${COLOR_OFF}"
      exit 1
    fi
  fi

  if [ "$Platform" = "Mac" ]; then
    # Homebrew installs OpenSSL in a non-default location on MacOS >= Mojave
    # 10.14 because MacOS has its own SSL implementation.  If we find the
    # typical Homebrew OpenSSL dir, load OPENSSL_ROOT_DIR so that cmake
    # will find the Homebrew version.
    dir=/usr/local/opt/openssl
    if [ -d $dir ]; then
        export OPENSSL_ROOT_DIR=$dir
    fi
  fi

  echo -e "${COLOR_GREEN}Building Folly ${COLOR_OFF}"
  mkdir -p "$FOLLY_BUILD_DIR"
  cd "$FOLLY_BUILD_DIR" || exit

  # check for environment variable. If
  if [[ -z "${MVFST_FOLLY_USE_JEMALLOC-}" ]]; then
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo         \
      -DCMAKE_PREFIX_PATH="$FOLLY_INSTALL_DIR"      \
      -DCMAKE_INSTALL_PREFIX="$FOLLY_INSTALL_DIR"   \
      ..
  else
    cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo         \
      -DCMAKE_PREFIX_PATH="$FOLLY_INSTALL_DIR"      \
      -DCMAKE_INSTALL_PREFIX="$FOLLY_INSTALL_DIR"   \
      -DFOLLY_USE_JEMALLOC=0                        \
      ..
  fi
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}Folly is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function setup_fizz() {
  FIZZ_DIR=$DEPS_DIR/fizz
  FIZZ_BUILD_DIR=$DEPS_DIR/fizz/build/
  if [ ! -d "$FIZZ_DIR" ] ; then
    echo -e "${COLOR_GREEN}[ INFO ] Cloning fizz repo ${COLOR_OFF}"
    git clone https://github.com/facebookincubator/fizz "$FIZZ_DIR"
    echo -e "${COLOR_GREEN}[ INFO ] install dependencies ${COLOR_OFF}"
  fi
  echo -e "${COLOR_GREEN}Building Fizz ${COLOR_OFF}"
  mkdir -p "$FIZZ_BUILD_DIR"
  cd "$FIZZ_BUILD_DIR" || exit
  cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo       \
    -DBUILD_TESTS=ON                            \
    -DCMAKE_PREFIX_PATH="$FIZZ_INSTALL_DIR"     \
    -DCMAKE_INSTALL_PREFIX="$FIZZ_INSTALL_DIR"  \
    "$FIZZ_DIR/fizz"
  make -j "$nproc"
  make install
  echo -e "${COLOR_GREEN}Fizz is installed ${COLOR_OFF}"
  cd "$BWD" || exit
}

function detect_platform() {
  unameOut="$(uname -s)"
  case "${unameOut}" in
      Linux*)     Platform=Linux;;
      Darwin*)    Platform=Mac;;
      *)          Platform="UNKNOWN:${unameOut}"
  esac
  echo -e "${COLOR_GREEN}Detected platform: $Platform ${COLOR_OFF}"
}

detect_platform
setup_folly
setup_fizz

# build mvfst:
cd "$MVFST_BUILD_DIR" || exit
cmake -DCMAKE_PREFIX_PATH="$FOLLY_INSTALL_DIR"    \
 -DCMAKE_INSTALL_PREFIX="$MVFST_INSTALL_DIR"      \
 -DCMAKE_BUILD_TYPE=RelWithDebInfo                \
 -DBUILD_TESTS=On                                 \
  ../..
make -j "$nproc"
echo -e "${COLOR_GREEN}MVFST build is complete. To run unit test: \
  cd _build/build && make test ${COLOR_OFF}"
