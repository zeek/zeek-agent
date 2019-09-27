#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

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
