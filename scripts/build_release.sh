#!/usr/bin/env bash

export CMAKE_VERSION="3.15.5"

main() {
  if [[ $# -ne 1 || "$1" == "--help" ]] ; then
    printUsage
    return 1
  fi

  local build_type="$1"
  if [[ "${build_type}" == "--system" ]] ; then
    printf "Building with the system compiler\n"

  elif [[ "${build_type}" == "--portable" ]] ; then
    printf "Building a portable version with the osquery toolchain\n"

  elif [[ "${build_type}" == "--portable-osquery" ]] ; then
    printf "Building a portable version with osquery support enabled\n"

  else
    printUsage
    printf "Invalid build type specified: ${build_type}\n"
    return 1
  fi

  if [ ! -d "build" ] ; then
    executeCommand \
      "Creating the build folder" \
      . \
      mkdir "build"
  fi

  if [ ! -d "package_build" ] ; then
    executeCommand \
      "Creating the package_build folder" \
      . \
      mkdir "package_build"
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
    sudo apt-get install clang clang-tidy-8 cppcheck ccache curl libssl-dev flex bison rpm doxygen -y

  executeCommand \
    "Synchronizing the submodules" \
    . \
    git submodule sync --recursive

  executeCommand \
    "Fetching the submodules" \
    . \
    git submodule update --init --recursive

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

  local osquery_toolchain_version="1.0.0"
  local osquery_toolchain_url="https://github.com/osquery/osquery-toolchain/releases/download/${osquery_toolchain_version}/osquery-toolchain-${osquery_toolchain_version}.tar.xz"
  local osquery_toolchain_tarball_path="$(realpath build/downloads)/osquery-toolchain-${osquery_toolchain_version}.tar.xz"
  local osquery_toolchain_install_path="$(realpath build)/osquery-toolchain"

  if [[ "${build_type}" == "--portable" || "${build_type}" == "--portable-osquery" ]] ; then
    if [ ! -d "${osquery_toolchain_install_path}" ] ; then
      if [ ! -f "${osquery_toolchain_tarball_path}" ] ; then
        executeCommand \
          "Downloading the osquery toolchain" \
          . \
          curl -L "${osquery_toolchain_url}" -o "${osquery_toolchain_tarball_path}"

      else
        printf " > Using cached osquery toolchain tarball: ${osquery_toolchain_tarball_path}\n"
      fi

      executeCommand \
        "Extracting the osquery toolchain" \
        "build" \
        tar xf "${osquery_toolchain_tarball_path}"

    else
      printf " > Using cached osquery toolchain directory: ${osquery_toolchain_install_path}\n"
    fi
  fi

  if [[ "${build_type}" == "--portable-osquery" ]] ; then
    if [ -d "osquery" ] ; then
      printf " i Using existing osquery folder\n"

    else
      executeCommand \
        "Downloading the osquery source code" \
        . \
        git clone --branch "4.1.1" https://github.com/osquery/osquery
    fi

    if [ ! -d "$(realpath osquery)/external/extension_zeek-agent" ] ; then
      executeCommand \
        "Linking the Zeek agent source folder to osquery/external" \
        . \
        ln -s "$(pwd)" "$(realpath osquery)/external/extension_zeek-agent"
    fi
  fi

  local ccache_folder="$(realpath build/ccache)"
  local install_prefix="/usr"
  local install_destination="$(realpath build/install)"

  export CCACHE_DIR="${ccache_folder}"
  export PATH="${osquery_toolchain_install_path}:${cmake_install_path}/bin:${PATH}"

  if [[ "${build_type}" == "--system" ]] ; then
    executeCommand \
      "Configuring the project (system build)" \
      "build" \
      cmake -DCMAKE_C_COMPILER:STRING=clang -DCMAKE_CXX_COMPILER:STRING=clang++ -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" -DZEEK_AGENT_ENABLE_DOCUMENTATION:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true -DZEEK_AGENT_ENABLE_SANITIZERS:BOOL=false -DZEEK_AGENT_ENABLE_TESTS:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true ..

  elif [[ "${build_type}" == "--portable" ]] ; then
    executeCommand \
      "Configuring the project (portable)" \
      "build" \
      cmake -DZEEK_AGENT_TOOLCHAIN_PATH="${osquery_toolchain_install_path}" -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DZEEK_AGENT_ENABLE_DOCUMENTATION:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true -DZEEK_AGENT_ENABLE_SANITIZERS:BOOL=false -DZEEK_AGENT_ENABLE_TESTS:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true ..

    executeCommand \
      "Building OpenSSL" \
      "build" \
      cmake --build . --target "thirdparty_openssl_builder"

  else
    executeCommand \
      "Configuring the project (portable-osquery)" \
      "build" \
      cmake -DOSQUERY_TOOLCHAIN_SYSROOT="${osquery_toolchain_install_path}" -DCMAKE_INSTALL_PREFIX:PATH="${install_prefix}" -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo -DZEEK_AGENT_ENABLE_DOCUMENTATION:BOOL=true -DZEEK_AGENT_ENABLE_INSTALL:BOOL=true -DZEEK_AGENT_ENABLE_TESTS:BOOL=true -DZEEK_AGENT_ENABLE_SANITIZERS:BOOL=false ../osquery
  fi

  local job_count="$(($(nproc)+1))"
  printf " i Building with ${job_count} jobs\n"

  executeCommand \
    "Building the project" \
    "build" \
    cmake --build . -j "${job_count}"

  executeCommand \
    "Generating the Doxygen documentation" \
    "build" \
    cmake --build . --target "doxygen"

  executeCommand \
    "Running the install target" \
    "build" \
    cmake --build . --target install -- DESTDIR="${install_destination}"

  executeCommand \
    "Running the tests" \
    "build" \
    cmake --build . --target "zeek_agent_tests"

  executeCommand \
    "Configuring the packaging project" \
    "package_build" \
    cmake -DZEEK_AGENT_INSTALL_PATH:PATH="${install_destination}" ../packaging

  executeCommand \
    "Generating packages" \
    "package_build" \
    cmake --build . --target "package"

  return 0
}

executeCommand() {
  local message="$1"
  printf "\n\n > ${message}\n\n\n"

  local working_directory="$2"

  ( cd "${working_directory}" && ${@:3} )
  if [[ $? -ne 0 ]] ; then
    printf " ! The following step has failed: ${message}\n"
    exit 1
  fi
}

printUsage() {
  printf "Usage:\n\tbuild_release.sh [--system | --portable | --portable-osquery]\n\n"
}

main $@
exit $?
