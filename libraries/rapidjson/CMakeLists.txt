cmake_minimum_required(VERSION 3.14)
project("rapidjson")

function(zeekAgentLibrariesRapidjson)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_rapidjson INTERFACE)

  target_link_libraries(thirdparty_rapidjson INTERFACE
    zeek_agent_cxx_settings
    zeek_agent_libraries_settings
  )

  target_compile_definitions(thirdparty_rapidjson INTERFACE
    RAPIDJSON_HAS_STDSTRING=1
  )

  target_include_directories(thirdparty_rapidjson INTERFACE
    SYSTEM INTERFACE
      "${library_root}/include"
  )
endfunction()

zeekAgentLibrariesRapidjson()
