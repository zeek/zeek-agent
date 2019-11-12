cmake_minimum_required(VERSION 3.14)
project("zeek-agent")

include("cmake/flags.cmake")
include("cmake/options.cmake")
include("cmake/utils.cmake")
include("cmake/tests.cmake")
include("cmake/ccache.cmake")

function(zeekAgent)
  generateSettingsTarget()
  generateRootZeekTestTarget()

  add_subdirectory("libraries")
  add_subdirectory("components")

  add_executable("${PROJECT_NAME}"
    src/main.cpp

    src/dummytable.h
    src/dummytable.cpp
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    zeek_agent_cxx_settings
    zeek_database
  )
endfunction()

configureCcache()
zeekAgent()
