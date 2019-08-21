cmake_minimum_required(VERSION 3.14)
project("catch2")

function(zeekAgentLibrariesCatch2)
  add_library(thirdparty_catch2 INTERFACE)

  target_include_directories(thirdparty_catch2 INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/single_include"
  )

  target_link_libraries(thirdparty_catch2 INTERFACE
    zeek_agent_cxx_settings
  )
endfunction()

zeekAgentLibrariesCatch2()
