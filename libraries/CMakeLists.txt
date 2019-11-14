cmake_minimum_required(VERSION 3.14)

function(zeekAgentLibraries)
  add_library(zeek_agent_libraries_settings INTERFACE)
  target_compile_options(zeek_agent_libraries_settings INTERFACE
    -Wno-error
  )

  add_subdirectory("sqlite")
  add_subdirectory("catch2")
  add_subdirectory("audit")
  add_subdirectory("rapidjson")
endfunction()

zeekAgentLibraries()
