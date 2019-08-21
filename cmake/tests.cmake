cmake_minimum_required(VERSION 3.14)

function(generateRootZeekTestTarget)
  if(NOT ZEEK_AGENT_ENABLE_TESTS)
    message(STATUS "zeek-agent: Tests are disabled")
  else()
    message(STATUS "zeek-agent: Tests are enabled")
  endif()

  add_custom_target(zeek_agent_tests)
endfunction()

function(attachZeekTest target_name)
  if(NOT ZEEK_AGENT_ENABLE_TESTS)
    return()
  endif()

  add_custom_target(
    "${target_name}_runner"
    COMMAND "$<TARGET_FILE:${target_name}>"
    COMMENT "Running: ${target_name}"
    VERBATIM
  )

  add_dependencies("${target_name}_runner" "${target_name}")
  add_dependencies(zeek_agent_tests "${target_name}_runner")
endfunction()

function(migrateProperty destination_target source_target property_name)
  get_target_property(source_property_value "${source_target}" "${property_name}")
  if("${source_property_value}" STREQUAL "source_property_value-NOTFOUND")
    return()
  endif()

  get_target_property(new_property_value "${destination_target}" "${property_name}")
  if("${new_property_value}" STREQUAL "new_property_value-NOTFOUND")
    unset(new_property_value)
  endif()

  list(APPEND new_property_value ${source_property_value})
  set_target_properties("${destination_target}" PROPERTIES "${property_name}" "${new_property_value}")
endfunction()

function(generateZeekAgentTest)
  if(NOT ZEEK_AGENT_ENABLE_TESTS)
    return()
  endif()

  cmake_parse_arguments(
    "ARGS"
    ""
    "SOURCE_TARGET"
    "SOURCES"
    ${ARGN}
  )

  if(NOT "${ARGS_UNPARSED_ARGUMENTS}" STREQUAL "")
    message(FATAL_ERROR "Invalid call to generateTestTarget(). One or more arguments are missing")
  endif()

  add_executable(
    "${ARGS_SOURCE_TARGET}_tests"
    ${ARGS_SOURCES}
  )

  target_link_libraries("${ARGS_SOURCE_TARGET}_tests" PRIVATE
    thirdparty_catch2
  )

  get_target_property(source_target_folder ${ARGS_SOURCE_TARGET} SOURCE_DIR)

  target_include_directories("${ARGS_SOURCE_TARGET}_tests" PRIVATE
    "${source_target_folder}/src"
  )

  set(property_list
    INCLUDE_DIRECTORIES
    INTERFACE_INCLUDE_DIRECTORIES

    LINK_LIBRARIES
    INTERFACE_LINK_LIBRARIES

    COMPILE_DEFINITIONS
    INTERFACE_COMPILE_DEFINITIONS

    COMPILE_OPTIONS
    INTERFACE_COMPILE_OPTIONS

    SOURCES
  )

  foreach(property_name ${property_list})
    migrateProperty("${ARGS_SOURCE_TARGET}_tests" "${ARGS_SOURCE_TARGET}" "${property_name}")
  endforeach()

  attachZeekTest("${ARGS_SOURCE_TARGET}_tests")
endfunction()
