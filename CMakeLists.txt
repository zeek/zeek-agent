cmake_minimum_required(VERSION 3.14)

include("cmake/options.cmake")
project("zeek-agent")

include("cmake/version.cmake")
include("cmake/flags.cmake")
include("cmake/utils.cmake")
include("cmake/tests.cmake")
include("cmake/ccache.cmake")

function(zeekAgent)
  generateSettingsTarget()
  generateRootZeekTestTarget()

  add_subdirectory("libraries")
  add_subdirectory("components")

  set(target_name_list
    "zeek-agent"
  )

  if(TARGET osqueryd)
    list(APPEND target_name_list "zeek-agent-osquery")
  endif()

  foreach(target_name ${target_name_list})
    add_executable("${target_name}"
      src/main.cpp

      src/zeekagent.h
      src/zeekagent.cpp

      src/zeekconnection.h
      src/zeekconnection.cpp

      src/uniquexxh64state.h
      src/uniquexxh64state.cpp

      src/logger.h
      src/logger.cpp

      src/configuration.h
      src/configuration.cpp

      src/queryscheduler.h
      src/queryscheduler.cpp

      src/tables/audisp/audispservice.h
      src/tables/audisp/audispservice.cpp

      src/tables/audisp/processeventstableplugin.h
      src/tables/audisp/processeventstableplugin.cpp

      src/tables/audisp/socketeventstableplugin.h
      src/tables/audisp/socketeventstableplugin.cpp
    )

    target_link_libraries("${target_name}" PRIVATE
      zeek_agent_cxx_settings
      zeek_audisp
      zeek_database
      zeek_logger
      zeek_service_manager
      zeek_configuration
      thirdparty_broker_lts
      thirdparty_xxhash
    )

    target_include_directories("${target_name}" PRIVATE
      src
    )

    if("${target_name}" STREQUAL "zeek-agent-osquery")
      target_compile_definitions("${target_name}" PRIVATE
        ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT
      )

      target_link_libraries("${target_name}" PRIVATE
        zeek_osquery_interface
      )
    endif()
  endforeach()

  if(ZEEK_AGENT_ENABLE_INSTALL)
    install(TARGETS ${target_name_list} DESTINATION "bin")
  endif()

  if(ZEEK_AGENT_ENABLE_DOCUMENTATION)
    add_subdirectory("documentation")
  endif()

  generateZeekAgentTest(
    SOURCE_TARGET
      "zeek-agent"

    SOURCES
      tests/main.cpp

      tests/utils.h
      tests/utils.cpp

      tests/processeventstableplugin.cpp
      tests/socketeventstableplugin.cpp
      tests/zeekconnection.cpp
  )
endfunction()

configureCcache()
zeekAgent()
