/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "globals.h"
#include "zeekdistributedplugin.h"
#include "zeekloggerplugin.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#include <osquery/sdk.h>

namespace osquery {
using ZeekLoggerPlugin = zeek::ZeekLoggerPlugin;
REGISTER_EXTERNAL(ZeekLoggerPlugin, "logger", "zeek_logger");

using ZeekDistributedPlugin = zeek::ZeekDistributedPlugin;
REGISTER_EXTERNAL(ZeekDistributedPlugin, "distributed", "zeek_distributed");
} // namespace osquery

int main(int argc, char* argv[]) {
  osquery::Initializer runner(argc, argv, osquery::ToolType::EXTENSION);

  auto status = osquery::startExtension("zeek", "1.0");
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    runner.requestShutdown(status.getCode());
  }

  runner.waitForShutdown();
  return 0;
}
