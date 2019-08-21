cmake_minimum_required(VERSION 3.14)
project("zeek_audisp")

function(zeekAgentComponentsAudisp)
  add_library("${PROJECT_NAME}"
    include/zeek/iaudispconsumer.h
    
    src/audispconsumer.h
    src/audispconsumer.cpp

    src/audit_utils.h
    src/audit_utils.cpp

    src/iauparseinterface.h
    src/auparseinterface.h
    src/auparseinterface.cpp
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
      thirdparty_audit
  )

  generateZeekAgentTest(
    SOURCE_TARGET
      "${PROJECT_NAME}"

    SOURCES
      tests/main.cpp

      tests/mockedauparseinterface.h
      tests/mockedauparseinterface.cpp

      tests/audit_utils.cpp
      tests/audispconsumer.cpp
  )
endfunction()

zeekAgentComponentsAudisp()
