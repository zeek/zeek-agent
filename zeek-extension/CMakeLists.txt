# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

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
endfunction()

zeekExtensionMain()
