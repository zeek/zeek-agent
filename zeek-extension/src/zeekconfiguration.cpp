/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "zeekconfiguration.h"

namespace zeek {
namespace {
const std::string kConfigurationPath{"/etc/osquery/zeek.conf"};
}

struct ZeekConfiguration::PrivateData final {
  std::string configuration_path;

  std::string server_address;
  std::uint16_t server_port;
  std::string group_list;
};

osquery::Status ZeekConfiguration::create(Ref& ref, const std::string& path) {
  try {
    ref.reset();

    auto ptr = new ZeekConfiguration(path);
    ref.reset(ptr);

    return osquery::Status::success();

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure(
        "Failed to create the ZeekConfiguration object");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ZeekConfiguration::~ZeekConfiguration() {}

const std::string& ZeekConfiguration::serverAddress() const {
  return d->server_address;
}

std::uint16_t ZeekConfiguration::serverPort() const {
  return d->server_port;
}

const std::string& ZeekConfiguration::groupList() const {
  return d->group_list;
}

ZeekConfiguration::ZeekConfiguration(const std::string& path)
    : d(new PrivateData) {
  d->configuration_path = path;

  d->server_address = "127.0.0.1";
  d->server_port = 9999U;
  d->group_list =
      "{ \"group1\": \"geo/de/hamburg\", \"group2\": \"orga/uhh/cs/iss\" }";
}
} // namespace zeek