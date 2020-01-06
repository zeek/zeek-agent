cmake_minimum_required(VERSION 3.14)
project("audit")

function(zeekAgentLibrariesAudit)
  generateLibaudit()
  generateLibauparse()

  add_library(thirdparty_audit INTERFACE)
  target_link_libraries(thirdparty_audit INTERFACE
    thirdparty_audit_libaudit
    thirdparty_audit_libauparse
  )
endfunction()

function(generateLibaudit)
  set(libaudit_root "${CMAKE_CURRENT_SOURCE_DIR}/src/lib")

  add_library(thirdparty_audit_libaudit
    "${libaudit_root}/deprecated.c"
    "${libaudit_root}/message.c"
    "${libaudit_root}/netlink.c"
    "${libaudit_root}/audit_logging.c"
    "${libaudit_root}/libaudit.c"
    "${libaudit_root}/lookup_table.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/strsplit.c"
  )

  target_compile_definitions(thirdparty_audit_libaudit PRIVATE
    _GNU_SOURCE
    HAVE_CONFIG_H
    HAVE_STRNDUPA
    PIC
  )

  target_include_directories(thirdparty_audit_libaudit PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/lib"
    "${libaudit_root}"
  )

  target_include_directories(thirdparty_audit_libaudit SYSTEM INTERFACE
    "${libaudit_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  target_link_libraries(thirdparty_audit_libaudit PRIVATE
    zeek_agent_c_settings
    zeek_agent_libraries_settings 
  )
endfunction()

function(generateLibauparse)
  set(libauparse_root "${CMAKE_CURRENT_SOURCE_DIR}/src/auparse")

  add_library(thirdparty_audit_libauparse
    "${libauparse_root}/data_buf.c"
    "${libauparse_root}/expression.c"
    "${libauparse_root}/lru.c"
    "${libauparse_root}/message.c"
    "${libauparse_root}/normalize-llist.c"
    "${libauparse_root}/normalize.c"
    "${libauparse_root}/nvlist.c"
    "${libauparse_root}/auditd-config.c"
    "${libauparse_root}/auparse.c"
    "${libauparse_root}/ellist.c"
    "${libauparse_root}/interpret.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common/strsplit.c"
  )

  target_compile_definitions(thirdparty_audit_libauparse PRIVATE
    _GNU_SOURCE
    HAVE_CONFIG_H
    HAVE_STRNDUPA
    PIC
  )

  target_include_directories(thirdparty_audit_libauparse PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated/auparse"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common"
  )

  target_include_directories(thirdparty_audit_libauparse SYSTEM INTERFACE
    "${libauparse_root}"
  )

  target_link_libraries(thirdparty_audit_libauparse PRIVATE
    zeek_agent_c_settings
    zeek_agent_libraries_settings
    thirdparty_audit_libaudit
  )
endfunction()

zeekAgentLibrariesAudit()
