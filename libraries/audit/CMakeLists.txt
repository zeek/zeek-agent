cmake_minimum_required(VERSION 3.14)
project("audit")

# To do: this should be imported from the source modules in osquery
function(zeekAgentLibrariesAudit)
  add_library(thirdparty_audit INTERFACE)

  target_link_libraries(thirdparty_audit INTERFACE
    audit
    auparse
  )
endfunction()

zeekAgentLibrariesAudit()
