#!/usr/bin/env bash

export CMAKE_VERSION="3.15.5"

main() {
  if [ ! -d "build" ] ; then
    executeCommand \
      "Creating the build folder" \
      . \
      mkdir "build"
  fi

  if [ ! -d "build/ccache" ] ; then
    executeCommand \
      "Creating the ccache folder" \
      . \
      mkdir "build/ccache"
  fi

  if [ ! -d "build/downloads" ] ; then
    executeCommand \
      "Creating the downloads folder" \
      . \
      mkdir "build/downloads"
  fi

  if [ ! -d "build/install" ] ; then
    executeCommand \
      "Creating the install folder" \
      . \
      mkdir "build/install"
  fi

  executeCommand \
    "Updating the system repositories" \
    . \
    sudo apt-get update

  executeCommand \
    "Installing system dependencies" \
    . \
    sudo apt-get install clang clang-tidy-8 cppcheck ccache curl libauparse-dev libaudit-dev libssl-dev -y

  local cmake_release_name="cmake-${CMAKE_VERSION}-Linux-x86_64"
  local cmake_url="https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/${cmake_release_name}.tar.gz"
  local cmake_tarball_path="$(realpath build/downloads)/${cmake_release_name}.tar.gz"
  local cmake_install_path="$(realpath build)/${cmake_release_name}"

  if [ ! -d "${cmake_install_path}" ] ; then
    if [ ! -f "${cmake_tarball_path}" ] ; then
      executeCommand \
        "Downloading CMake" \
        . \
        curl -L "${cmake_url}" -o "${cmake_tarball_path}"

    else
      printf " > Using cached CMake tarball: ${cmake_tarball_path}\n"
    fi

    executeCommand \
      "Extracting CMake" \
      "build" \
      tar xzf "${cmake_tarball_path}"

  else
    printf " > Using cached CMake install directory: ${cmake_install_path}\n"
  fi

  local ccache_folder="$(realpath build/ccache)"
  local install_prefix="$(realpath build/install)"

  export CCACHE_DIR="${ccache_folder}"
  export PATH="${cmake_install_path}/bin:${PATH}"

  executeCommand \
    "Fetching the submodules" \
    . \
    git submodule update --init --recursive

  executeCommand \
    "Configuring the project" \
    "build" \
    cmake -DCMAKE_C_COMPILER:STRING=clang -DCMAKE_CXX_COMPILER:STRING=clang++ -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" -DCMAKE_BUILD_TYPE:STRING=Debug -DZEEK_AGENT_ENABLE_TESTS:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true -DZEEK_AGENT_ENABLE_SANITIZERS:BOOL=true ..

  executeCommand \
    "Building the project" \
    "build" \
    cmake --build . -j `nproc`

  executeCommand \
    "Running the install target" \
    "build" \
    cmake --build . --target install

  printf " > Running the tests\n\n"

  cd "build"
  cmake --build . --target zeek_agent_tests
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

executeCommand() {
  local log_file="$(mktemp)"
  printf "$(date)\n\n" > "${log_file}"

  local message="$1"
  printf " > ${message}\n"

  local working_directory="$2"

  ( cd "${working_directory}" && ${@:3} >> "${log_file}" 2>&1 )
  if [[ $? -ne 0 ]] ; then
    abort "${log_file}"
  fi
}

abort() {
  local log_file="$1"

  printf " ! The operation has failed\n"

  printf "\n====\n\n"
  cat "${log_file}"
  exit 1
}

main $@
exit $?
