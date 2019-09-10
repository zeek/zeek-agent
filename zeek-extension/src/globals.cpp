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
  auto status = ZeekConfiguration::create(configuration, kConfigurationPath);

  if (!status) {
    LOG(ERROR) << status.getMessage();
    return false;
  }

  status = IQueryManager::create(query_manager);
  if (!status) {
    LOG(ERROR) << status.getMessage();
    return false;
  }

  IBrokerManager::Configuration broker_config;
  broker_config.server_address = configuration->serverAddress();
  broker_config.server_port = configuration->serverPort();
  broker_config.server_group_list = configuration->groupList();

  broker_config.certificate_authority = configuration->certificateAuthority();
  broker_config.client_certificate = configuration->clientCertificate();
  broker_config.client_key = configuration->clientKey();

  status = IBrokerManager::create(broker_manager, broker_config, query_manager);

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
