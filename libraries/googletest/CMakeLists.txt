#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(googletestMain)
  # todo(alessandro): Remove this once the extension is migrated to the
  # osquery 4.x SDK
  add_library(thirdparty_googletest INTERFACE)
  target_link_libraries(thirdparty_googletest INTERFACE
    "${CMAKE_BINARY_DIR}/third-party/googletest/googlemock/gtest/libgtest.a"
    "${CMAKE_BINARY_DIR}/third-party/googletest/googlemock/gtest/libgtest_main.a"
  )

  target_include_directories(thirdparty_googletest INTERFACE
    "${CMAKE_SOURCE_DIR}/third-party/googletest/googletest/include"
    "${CMAKE_SOURCE_DIR}/third-party/googletest/googlemock/include"
  )

  add_dependencies(thirdparty_googletest
    gtest
    gtest_main
  )

  find_package(Threads)
  target_link_libraries(thirdparty_googletest INTERFACE
    ${CMAKE_THREAD_LIBS_INIT}
  )
endfunction()

googletestMain()
