# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(importBroker)
  add_library(thirdparty_broker STATIC IMPORTED GLOBAL)
  set_target_properties(thirdparty_broker PROPERTIES IMPORTED_LOCATION
    /usr/local/osquery/lib/libbroker.a
  )

  target_include_directories(thirdparty_broker SYSTEM INTERFACE
    /usr/local/osquery/include
  )
endfunction()

function(importCaf)
  add_library(thirdparty_caf INTERFACE)

  set(library_name_list
    caf_core
    caf_io
    caf_openssl
  )

  foreach(library_name ${library_name_list})
    set(full_library_name "thirdparty_${library_name}")

    add_library("${full_library_name}" STATIC IMPORTED GLOBAL)
    set_target_properties("${full_library_name}" PROPERTIES IMPORTED_LOCATION
      "/usr/local/osquery/lib/lib${library_name}_static.a"
    )

    target_include_directories("${full_library_name}" SYSTEM INTERFACE
      /usr/local/osquery/include
    )

    target_link_libraries(thirdparty_caf INTERFACE
      "${full_library_name}"
    )
  endforeach()

  importOpenSSL()
  target_link_libraries(thirdparty_caf_openssl INTERFACE
    thirdparty_openssl
  )
endfunction()

function(importOpenSSL)
  add_library(thirdparty_openssl STATIC IMPORTED GLOBAL)
  set_target_properties(thirdparty_openssl PROPERTIES IMPORTED_LOCATION
    /usr/local/osquery/lib/libssl.a
  )

  target_include_directories(thirdparty_openssl SYSTEM INTERFACE
    /usr/local/osquery/include
  )
endfunction()
