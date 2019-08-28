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
#include "configurationchecker.h"

#include <zeek-remote/utils.h>

namespace zeek {
namespace {
const std::string kConfigurationPath{"/etc/osquery/zeek.conf"};

bool initializeGlobalsHelper() {
  auto status =
      zeek::ZeekConfiguration::create(zeek::configuration, kConfigurationPath);

  if (!status) {
    LOG(ERROR) << status.getMessage();
    return false;
  }

  status = zeek::IQueryManager::create(zeek::query_manager);
  if (!status) {
    LOG(ERROR) << status.getMessage();
    return false;
  }

  auto server_address = zeek::configuration->serverAddress();
  auto server_port = zeek::configuration->serverPort();
  auto server_group_list = zeek::configuration->groupList();

  status = zeek::IBrokerManager::create(zeek::broker_manager,
                                        server_address,
                                        server_port,
                                        server_group_list,
                                        zeek::query_manager);
  if (!status) {
    LOG(ERROR) << status.getMessage();
    return false;
  }

  return true;
}
} // namespace

ZeekConfiguration::Ref configuration;
IQueryManager::Ref query_manager;
IBrokerManager::Ref broker_manager;

osquery::Status initializeGlobals() {
  static bool initialized = initializeGlobalsHelper();
  if (!initialized) {
    return osquery::Status::failure("Failed to initialize the Zeek components");
  }

  return osquery::Status::success();
}
} // namespace zeek
