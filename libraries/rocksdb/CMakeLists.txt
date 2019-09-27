#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(rocksdbMain)
  # todo(alessandro): Remove this once the extension is migrated to the
  # osquery 4.x SDK
  add_library(thirdparty_rocksdb INTERFACE)
  target_link_libraries(thirdparty_rocksdb INTERFACE
    rocksdb_lite
  )
endfunction()

rocksdbMain()
