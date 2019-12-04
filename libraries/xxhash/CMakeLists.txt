cmake_minimum_required(VERSION 3.14)
project("xxhash")

function(zeekAgentLibrariesXxhash)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_xxhash
    "${library_root}/xxh3.h"

    "${library_root}/xxhash.h"
    "${library_root}/xxhash.c"
  )

  configure_file(
    "${library_root}/xxhash.h"
    "${CMAKE_CURRENT_BINARY_DIR}/include/xxhash.h"
    COPYONLY
  )

  target_include_directories(thirdparty_xxhash
    PRIVATE
      "${library_root}"
      "${CMAKE_CURRENT_BINARY_DIR}/include"
  )

  target_include_directories(thirdparty_xxhash
    SYSTEM INTERFACE
      "${CMAKE_CURRENT_BINARY_DIR}/include"
  )

  target_link_libraries(thirdparty_xxhash INTERFACE
    zeek_agent_c_settings
  )
endfunction()

zeekAgentLibrariesXxhash()
