#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(zeekRemoteMain)
  generateZeekRemote()

  add_subdirectory(tests)
endfunction()

function(generateZeekRemote)
  add_library(zeek-remote
    include/zeek-remote/ibrokermanager.h
    include/zeek-remote/iquerymanager.h
    include/zeek-remote/types.h
    include/zeek-remote/utils.h

    src/idatabaseinterface.h

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
    libcaf_core
    libcaf_core_shared
    libcaf_io_shared
    libcaf_openssl_shared
    broker
    zeek_cxx_settings
  )
endfunction()

zeekRemoteMain()
