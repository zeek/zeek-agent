# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(generateZeekSettingsTarget)
  add_library(zeek_common_settings INTERFACE)
  target_compile_options(zeek_common_settings INTERFACE
    -Wall
    -Wextra
    -Werror
    -Weverything
    -pedantic
  )

  add_library(zeek_c_settings INTERFACE)
  target_link_libraries(zeek_c_settings INTERFACE zeek_common_settings)

  add_library(zeek_cxx_settings INTERFACE)
  target_link_libraries(zeek_cxx_settings INTERFACE zeek_common_settings)

  # The CAF and Broker versions we have will not compile correctly
  # with C++14 and above
  target_compile_features(zeek_c_settings INTERFACE c_std_11)
  target_compile_features(zeek_cxx_settings INTERFACE cxx_std_14)
endfunction()
