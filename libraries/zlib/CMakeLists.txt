cmake_minimum_required(VERSION 3.14)
project("zlib")

function(zeekAgentLibrariesZlib)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_zlib EXCLUDE_FROM_ALL
    "${library_root}/adler32.c"
    "${library_root}/compress.c"
    "${library_root}/crc32.c"
    "${library_root}/deflate.c"
    "${library_root}/gzclose.c"
    "${library_root}/gzlib.c"
    "${library_root}/gzread.c"
    "${library_root}/gzwrite.c"
    "${library_root}/infback.c"
    "${library_root}/inffast.c"
    "${library_root}/inflate.c"
    "${library_root}/inftrees.c"
    "${library_root}/trees.c"
    "${library_root}/uncompr.c"
    "${library_root}/zutil.c"
  )

  target_compile_definitions(thirdparty_zlib PRIVATE
    PIC
  )

  target_link_libraries(thirdparty_zlib PRIVATE
    zeek_agent_c_settings
    zeek_agent_libraries_settings
  )

  target_include_directories(thirdparty_zlib
    PRIVATE
      "${library_root}"
  )

  target_include_directories(thirdparty_zlib
    SYSTEM INTERFACE
      "${library_root}"
  )
endfunction()

zeekAgentLibrariesZlib()

