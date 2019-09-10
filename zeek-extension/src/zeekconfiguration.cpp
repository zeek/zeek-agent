/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/logger.h>
#include <osquery/status.h>

#include "configurationchecker.h"
#include "zeekconfiguration.h"

#include <fstream>
#include <unordered_map>

namespace zeek {
namespace {
const std::string kConfigurationPath{"/etc/osquery/zeek.conf"};
const std::string kDefaultServerAddress{"127.0.0.1"};
const std::uint16_t kDefaultServerPort{9999U};

// clang-format off
const std::vector<std::string> kDefaultGroupList = {
  "geo/de/hamburg",
  "orga/uhh/cs/iss"
};
// clang-format on

// clang-format off
const ConfigurationChecker::Constraints kConfigurationConstraints = {
  {
    "server_address",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "",
      true
    }
  },

  {
    "server_port",

    {
      ConfigurationChecker::MemberConstraint::Type::UInt16,
      false,
      "",
      true
    }
  },

  {
    "group_list",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      true,
      "",
      true
    }
  },

  {
    "certificate_authority",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "authentication",
      false
    }
  },

  {
    "certificate",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "authentication",
      false
    }
  },

  {
    "key",

    {
      ConfigurationChecker::MemberConstraint::Type::String,
      false,
      "authentication",
      false
    }
  },
};
// clang-format on
} // namespace

struct ZeekConfiguration::PrivateData final {
  Context context;
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
  return d->context.server_address;
}

std::uint16_t ZeekConfiguration::serverPort() const {
  return d->context.server_port;
}

const std::vector<std::string>& ZeekConfiguration::groupList() const {
  return d->context.group_list;
}

const std::string& ZeekConfiguration::certificateAuthority() const {
  return d->context.certificate_authority;
}

const std::string& ZeekConfiguration::clientCertificate() const {
  return d->context.client_certificate;
}

const std::string& ZeekConfiguration::clientKey() const {
  return d->context.client_key;
}

osquery::Status ZeekConfiguration::parseConfigurationData(
    Context& context, const std::string& json) {
  context = {};

  rapidjson::Document document;
  document.Parse(json);

  ConfigurationChecker::Ref config_checker;
  auto status =
      ConfigurationChecker::create(config_checker, kConfigurationConstraints);

  if (!status.ok()) {
    return status;
  }

  status = config_checker->validate(document);
  if (!status.ok()) {
    return status;
  }

  context.server_address = document["server_address"].GetString();

  context.server_port =
      static_cast<std::uint16_t>(document["server_port"].GetInt());

  const auto& group_list = document["group_list"];

  for (auto i = 0; i < group_list.Size(); ++i) {
    const auto& group = group_list[i].GetString();
    context.group_list.push_back(group);
  }

  if (document.HasMember("authentication")) {
    const auto& auth_object = document["authentication"];

    if (auth_object.HasMember("certificate_authority")) {
      context.certificate_authority =
          auth_object["certificate_authority"].GetString();
    }

    if (auth_object.HasMember("client_certificate")) {
      context.client_certificate =
          auth_object["client_certificate"].GetString();
    }

    if (auth_object.HasMember("client_key")) {
      context.client_key = auth_object["client_key"].GetString();
    }
  }

  return osquery::Status::success();
}

ZeekConfiguration::ZeekConfiguration(const std::string& path)
    : d(new PrivateData) {
  std::ifstream configuration_file(path);

  std::stringstream sstream;
  sstream << configuration_file.rdbuf();

  bool use_default_settings = true;
  if (configuration_file) {
    auto status = parseConfigurationData(d->context, sstream.str());
    if (status.ok()) {
      use_default_settings = false;

    } else {
      LOG(ERROR) << "Failed to parse the configuration file: "
                 << status.getMessage();
    }
  }

  if (use_default_settings) {
    LOG(WARNING) << "Using default configuration settings";

    d->context.server_address = kDefaultServerAddress;
    d->context.server_port = kDefaultServerPort;
    d->context.group_list = kDefaultGroupList;
  }

  VLOG(1) << "Zeek server address: " << d->context.server_address << ":"
          << d->context.server_port;

  std::stringstream group_list;
  for (const auto& group : d->context.group_list) {
    if (!group_list.str().empty()) {
      group_list << ", ";
    }

    group_list << group;
  }

  VLOG(1) << "Zeek group list: " << group_list.str();
}
} // namespace zeek