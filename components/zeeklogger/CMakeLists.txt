cmake_minimum_required(VERSION 3.14)
project("zeek_logger")

function(zeekAgentComponentsLogger)
  add_library("${PROJECT_NAME}"
    include/zeek/izeeklogger.h

    src/zeeklogger.h
    src/zeeklogger.cpp

    src/zeekloggertableplugin.h
    src/zeekloggertableplugin.cpp
  )

  target_include_directories("${PROJECT_NAME}"
    PRIVATE include
    SYSTEM INTERFACE include
  )

  target_link_libraries("${PROJECT_NAME}"
    PRIVATE
      zeek_agent_cxx_settings

    PUBLIC
      zeek_utils
      zeek_database
  )
endfunction()

zeekAgentComponentsLogger()
