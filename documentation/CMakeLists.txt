cmake_minimum_required(VERSION 3.14)
project("zeek-agent-documentation")

function(zeekAgentDocumentation)
  set(source_folder_list
    "components"
    "src"
  )

  find_program(doxygen_executable_path doxygen)
  if("${doxygen_executable_path}" STREQUAL "doxygen_executable_path-NOTFOUND")
    message(FATAL_ERROR "The Doxygen command was not found")
  endif()

  set(ZEEK_AGENT_DOCUMENTATION_BUILD_PATH "${CMAKE_CURRENT_BINARY_DIR}/docs")

  # We may be located inside the osquery source tree; use a relative path
  # for the INPUT field
  set(zeek_agent_root "${CMAKE_CURRENT_SOURCE_DIR}/..")

  foreach(source_folder ${source_folder_list})
    set(ZEEK_AGENT_DOCUMENTATION_SOURCE_PATH "${ZEEK_AGENT_DOCUMENTATION_SOURCE_PATH} ${zeek_agent_root}/${source_folder}")
  endforeach()

  configure_file(
    "doxygen.conf.inc"
    "${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf"
    @ONLY
  )

  add_custom_target(doxygen
    COMMAND doxygen "${CMAKE_CURRENT_BINARY_DIR}/doxygen.conf"
    COMMENT "Generating Doxygen documentation..."
    VERBATIM
  )
endfunction()

zeekAgentDocumentation()
