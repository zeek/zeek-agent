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

    src/zeekagent.h
    src/zeekagent.cpp

    src/logger.h
    src/logger.cpp

    src/tables/audisp/audispservice.h
    src/tables/audisp/audispservice.cpp

    src/tables/audisp/processeventstableplugin.h
    src/tables/audisp/processeventstableplugin.cpp

    src/tables/audisp/socketeventstableplugin.h
    src/tables/audisp/socketeventstableplugin.cpp
  )

  target_link_libraries("${PROJECT_NAME}" PRIVATE
    zeek_agent_cxx_settings
    zeek_audisp
    zeek_database
    zeek_logger
    zeek_service_manager
  )

  target_include_directories("${PROJECT_NAME}" PRIVATE
    src
  )

  generateZeekAgentTest(
    SOURCE_TARGET
      "${PROJECT_NAME}"

    SOURCES
      tests/main.cpp

      tests/utils.h
      tests/utils.cpp

      tests/processeventstableplugin.cpp
      tests/socketeventstableplugin.cpp
  )
endfunction()

configureCcache()
zeekAgent()
