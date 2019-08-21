# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(sqliteMain)
  # todo(alessandro): Remove this once the extension is migrated to the
  # osquery 4.x SDK
  add_library(thirdparty_sqlite INTERFACE)
  target_link_libraries(thirdparty_sqlite INTERFACE
    osquery_sqlite
  )

  target_include_directories(thirdparty_sqlite SYSTEM INTERFACE
    "${CMAKE_SOURCE_DIR}/third-party/sqlite3"
  )
endfunction()

sqliteMain()
