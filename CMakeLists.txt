# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)
project(osquery-zeek)

include(cmake/utils.cmake)
include(cmake/options.cmake)

function(osqueryZeekMain)
  if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    message(WARNING "osquery-zeek: Unsupported platform")
    return()
  endif()

  generateZeekSettingsTarget()
  geneateZeekTestsTarget()

  set(subdirectory_list
    libraries
    zeek-remote
    zeek-extension
  )

  foreach(subdirectory ${subdirectory_list})
    add_subdirectory("${subdirectory}")
  endforeach()
endfunction()

function(geneateZeekTestsTarget)
  if(ZEEK_BUILD_TESTING)
    add_custom_target(zeek_tests)
    message(STATUS "osquery-zeek tests are enabled")

  else()
    add_custom_target(zeek_tests
      COMMAND "${CMAKE_COMMAND}" -E echo "The osquery-zeek tests are not available. Enable the ZEEK_BUILD_TESTING option to compile them"
      VERBATIM
    )

    message(STATUS "osquery-zeek tests are disabled")
  endif()
endfunction()

function(addZeekTest)
  if(NOT ZEEK_BUILD_TESTING)
    return()
  endif()

  cmake_parse_arguments(
    ARGS
    ""
    "NAME"
    "SOURCES;LINK_LIBRARIES;INCLUDE_DIRECTORIES"
    ${ARGN}
  )

  set(ARGS_NAME "${ARGS_NAME}_test")

  add_executable("${ARGS_NAME}"
    ${ARGS_SOURCES}
  )

  if(NOT "${ARGS_INCLUDE_DIRECTORIES}" STREQUAL "")
    target_include_directories("${ARGS_NAME}" PRIVATE
      ${ARGS_INCLUDE_DIRECTORIES}
    )
  endif()

  target_link_libraries("${ARGS_NAME}" PRIVATE
    thirdparty_googletest
    zeek_cxx_settings
    ${ARGS_LINK_LIBRARIES}
  )

  add_custom_target(
    "${ARGS_NAME}_runner"
    COMMAND "$<TARGET_FILE:${ARGS_NAME}>"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Running test: ${ARGS_NAME}"
    VERBATIM
  )

  add_dependencies(
    "${ARGS_NAME}_runner"
    "${ARGS_NAME}"
  )

  add_dependencies(zeek_tests "${ARGS_NAME}_runner")
endfunction()

osqueryZeekMain()
