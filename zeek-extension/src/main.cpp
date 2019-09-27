/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
