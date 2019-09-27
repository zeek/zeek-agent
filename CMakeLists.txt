#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)
project(osquery-zeek)

set(CMAKE_EXPORT_COMPILE_COMMANDS true CACHE BOOL "Set to true to generate the compile_commands.json file" FORCE)

include(cmake/utils.cmake)
include(cmake/options.cmake)

function(osqueryZeekMain)
  if(NOT "${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
    message(WARNING "osquery-zeek: Unsupported platform")
    return()
  endif()

  generateZeekSettingsTarget()
  geneateZeekTestsTarget()
  generateClangTidyTarget()
  generateCppcheckTarget()

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
    add_custom_target(run_zeek_tests)

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
    "NAME;TARGET"
    "SOURCES;LINK_LIBRARIES;INCLUDE_DIRECTORIES"
    ${ARGN}
  )

  list(FIND ARGS_KEYWORDS_MISSING_VALUES "TARGET" target_keyword_index)
  if(NOT "${ARGS_TARGET}" STREQUAL "" OR NOT ${target_keyword_index} EQUAL -1)
    getTargetSourceFileList("${ARGS_TARGET}" temp_additional_source_file_list)

    foreach(source_file ${temp_additional_source_file_list})
      if("${source_file}" MATCHES "\/main.cpp$")
        continue()
      endif()

      list(APPEND additional_source_file_list
        "${source_file}"
      )
    endforeach()
  endif()

  set(ARGS_NAME "zeek_${ARGS_NAME}_test")
  add_executable("${ARGS_NAME}"
    ${ARGS_SOURCES}
    ${additional_source_file_list}
  )

  if(NOT "${ARGS_INCLUDE_DIRECTORIES}" STREQUAL "")
    target_include_directories("${ARGS_NAME}" PRIVATE
      ${ARGS_INCLUDE_DIRECTORIES}
    )
  endif()

  target_link_libraries("${ARGS_NAME}" PRIVATE
    thirdparty_googletest
    zeek_cxx_settings
    libosquery
    c++abi

    ${ARGS_LINK_LIBRARIES}
  )

  add_dependencies(zeek_tests "${ARGS_NAME}")

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

  add_dependencies(run_zeek_tests "${ARGS_NAME}_runner")
endfunction()

function(getTargetSourceFileList target_name output_variable)
  get_target_property(source_file_list "${target_name}" SOURCES)
  get_target_property(source_directory "${target_name}" SOURCE_DIR)

  foreach(source_file ${source_file_list})
    list(APPEND output
      "${source_directory}/${source_file}"
    )
  endforeach()

  set("${output_variable}" ${output} PARENT_SCOPE)
endfunction()

osqueryZeekMain()
