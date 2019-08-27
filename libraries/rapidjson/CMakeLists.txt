# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(rapidjsonMain)
  generateRapidjson()
endfunction()

function(generateRapidjson)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_rapidjson INTERFACE)

  target_link_libraries(thirdparty_rapidjson INTERFACE
    zeek_common_settings
  )

  target_include_directories(thirdparty_rapidjson SYSTEM INTERFACE
    "${library_root}/src/include"
  )

  target_compile_features(thirdparty_rapidjson INTERFACE cxx_std_11)
endfunction()

rapidjsonMain()
