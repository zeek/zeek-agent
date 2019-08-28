/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "zeekloggerplugin.h"
#include "globals.h"

namespace zeek {
bool _logger_event_type = false;
bool _disable_distributed = false;
std::string _distributed_plugin{"zeek_distributed"};

osquery::Status ZeekLoggerPlugin::setUp() {
  if (_disable_distributed) {
    return osquery::Status::failure("The distributed service is disabled");
  }

  if (_distributed_plugin != "zeek_distributed") {
    return osquery::Status::failure("The Zeek distributed service is disabled");
  }

  if (_logger_event_type) {
    return osquery::Status::failure(
        "The Zeek logger cannot use event type logging");
  }

  auto status = initializeGlobals();
  if (!status.ok()) {
    return status;
  }

  return osquery::Status::success();
}

osquery::Status ZeekLoggerPlugin::logString(const std::string& s) {
  osquery::QueryLogItem item;

  auto status = deserializeQueryLogItemJSON(s, item);
  if (!status) {
    return osquery::Status::failure("Failed to deserialize");
  }

  return broker_manager->logQueryLogItemToZeek(item);
}

osquery::Status ZeekLoggerPlugin::logSnapshot(const std::string& s) {
  return logString(s);
}

osquery::Status ZeekLoggerPlugin::logStatus(
    const std::vector<osquery::StatusLogLine>& log) {
  return osquery::Status::failure("Not implemented");
}

void ZeekLoggerPlugin::init(const std::string& name,
                            const std::vector<osquery::StatusLogLine>& log) {}
} // namespace zeek
