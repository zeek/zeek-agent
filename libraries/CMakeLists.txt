# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

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

    # todo(alessandro): Uncomment this when we move to osquery 4.x
    # rapidjson

    actor-framework
    broker
  )

  foreach(library ${library_list})
    add_subdirectory("${library}")
  endforeach()
endfunction()

zeekLibrariesMain()
