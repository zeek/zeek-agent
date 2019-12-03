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
  add_subdirectory("broker")
  add_subdirectory("xxhash")

  if(NOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" STREQUAL "")
    # If we are building with the osquery toolchain, then we will
    # also build OpenSSL from source. If that is the case, ZLIB
    # is a dependency
    add_subdirectory("zlib")
  endif()

  add_subdirectory("openssl")
endfunction()

zeekAgentLibraries()
