# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(generateZeekSettingsTarget)
  add_library(zeek_common_settings INTERFACE)
  target_compile_options(zeek_common_settings INTERFACE
    -Wall
    -Wextra
    -Werror
    -Weverything
    -pedantic
  )

  add_library(zeek_c_settings INTERFACE)
  target_link_libraries(zeek_c_settings INTERFACE zeek_common_settings)

  add_library(zeek_cxx_settings INTERFACE)
  target_link_libraries(zeek_cxx_settings INTERFACE zeek_common_settings)

  # The CAF and Broker versions we have will not compile correctly
  # with C++14 and above
  target_compile_features(zeek_c_settings INTERFACE c_std_11)
  target_compile_features(zeek_cxx_settings INTERFACE cxx_std_14)
endfunction()

function(generateClangTidyTarget)
  if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    message(STATUS "clang-tidy: Disabled, because the current platform is not supported")
    return()
  endif()

  if(NOT CMAKE_EXPORT_COMPILE_COMMANDS)
    message(STATUS "clang-tidy: Disabled, because CMAKE_EXPORT_COMPILE_COMMANDS was set to false")
    return()
  endif()

  find_program(
    ZEEK_CLANG_TIDY_PATH

    NAMES
      run-clang-tidy-8
      run-clang-tidy-7
      run-clang-tidy-6
      run-clang-tidy
  )

  if("${ZEEK_CLANG_TIDY_PATH}" STREQUAL "ZEEK_CLANG_TIDY_PATH-NOTFOUND")
    message(STATUS "clang-tidy: Disabled, because the run-clang-tidy script could not be found")
    return()
  endif()

  if(NOT ZEEK_BUILD_TESTING)
    message(WARNING "clang-tidy: Zeek tests will not be checked, because ZEEK_BUILD_TESTING is set to false)")
  endif()

  add_custom_target(
    zeek_tidy
    COMMAND "${ZEEK_CLANG_TIDY_PATH}" -p "${CMAKE_BINARY_DIR}" "-extra-arg=-include" "-extra-arg=${CMAKE_CURRENT_SOURCE_DIR}/libraries/clang-tidy/include/compat.h" "(zeek)(?!.*libraries.*)"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Running clang-tidy on osquery-zeek..."
    VERBATIM
  )

  message(STATUS "clang-tidy: Enabled on osquery-zeek")
endfunction()
