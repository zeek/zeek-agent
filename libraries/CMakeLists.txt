#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(zeekLibrariesMain)
  add_library(zeek_thirdparty_module_settings INTERFACE)
  target_compile_options(zeek_thirdparty_module_settings INTERFACE
    -Wno-everything
    -Wno-all
    -Wno-error
  )

  set(library_list
    # todo(alessandro): Remove these once the extension is migrated to the
    # osquery 4.x SDK
    openssl
    sqlite
    rocksdb
    googletest

    # todo(alessandro): Uncomment these once the extension is migrated to the
    # osquery 4.x SDK
    # rapidjson
    actor-framework
    broker
  )

  foreach(library ${library_list})
    add_subdirectory("${library}")
  endforeach()
endfunction()

zeekLibrariesMain()
