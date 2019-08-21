# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(zeekRemoteMain)
  add_library(zeek-remote
    include/zeek-remote/ibrokermanager.h
    include/zeek-remote/iquerymanager.h
    include/zeek-remote/types.h
    include/zeek-remote/utils.h

    src/brokermanager.h
    src/brokermanager.cpp

    src/querymanager.h
    src/querymanager.cpp

    src/types.cpp
    src/utils.cpp
  )

  target_include_directories(zeek-remote PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )

  target_link_libraries(zeek-remote PUBLIC
    thirdparty_broker
    thirdparty_caf
    zeek_cxx_settings
  )
endfunction()

zeekRemoteMain()
