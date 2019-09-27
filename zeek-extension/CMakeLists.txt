#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(zeekExtensionMain)
  add_osquery_extension("${PROJECT_NAME}"
    src/zeekloggerplugin.h
    src/zeekloggerplugin.cpp

    src/zeekdistributedplugin.h
    src/zeekdistributedplugin.cpp

    src/zeekconfiguration.h
    src/zeekconfiguration.cpp

    src/configurationchecker.h
    src/configurationchecker.cpp

    src/globals.h
    src/globals.cpp

    src/main.cpp
  )

  target_link_libraries("${PROJECT_NAME}"
    zeek-remote

    # Uncomment this when moving to osquery 4.x
    # thirdparty_rapidjson
  )

  add_subdirectory(tests)
endfunction()

zeekExtensionMain()
