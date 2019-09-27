#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

#!/usr/bin/env bash

OSQUERY_VERSION="3.3.2"

main() {
  local osquery_src_folder="build/osquery-extension-sdk"
  local zeek_extension_folder="${osquery_src_folder}/external/extension_osquery-zeek"

  executeCommand \
    "Updating the system repositories" \
    . \
    sudo apt-get update

  executeCommand \
    "Installing system dependencies" \
    . \
    sudo apt-get install clang clang-tidy-8 cppcheck

  executeCommand \
    "Fetching the osquery-zeek git submodules" \
    . \
    git submodule update --init --recursive

  if [[ ! -d "${osquery_src_folder}" ]] ; then
    executeCommand \
      "Cloning the osquery repository" \
      . \
      git clone https://github.com/osquery/osquery "${osquery_src_folder}"
  fi

  executeCommand \
    "Updating the osquery repository" \
    "${osquery_src_folder}" \
    git fetch --all

  executeCommand \
    "Selecting osquery version ${OSQUERY_VERSION}" \
    "${osquery_src_folder}" \
    git checkout ${OSQUERY_VERSION}

  if [[ ! -d "${zeek_extension_folder}" ]] ; then
    executeCommand \
      "Linking the extension src folder" \
      . \
      ln -s "$(realpath .)" "${zeek_extension_folder}"
  fi

  executeCommand \
    "Installing the osquery dependencies" \
    "${osquery_src_folder}" \
    make sysprep

  export ZEEK_BUILD_TESTING=1

  executeCommand \
    "Building the osquery-zeek tests" \
    "${osquery_src_folder}" \
    make zeek_tests -j $(nproc)

  
  printf "\nRunning the osquery-zeek tests and checks...\n\n===\n\n"
  target_name_list=( run_zeek_tests zeek_tidy zeek_cppcheck )

  local exit_code=0

  for target_name in "${target_name_list[@]}" ; do
    ( cd "${osquery_src_folder}" && make "${target_name}" )
    if [[ $? -ne 0 ]] ; then
      printf "Target ${target_name} has failed\n"
      exit_code=1
    fi

    printf "\n\n"
  done

  return ${exit_code}
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
