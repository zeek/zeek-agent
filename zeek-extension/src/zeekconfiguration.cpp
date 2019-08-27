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

#include <unordered_map>

#include <osquery/sdk.h>

// todo(alessandro): this is defined project-wide by the osquery sdk; we
// can remove this when switching to version 4.x
#ifdef RAPIDJSON_NO_SIZETYPEDEFINE
#undef RAPIDJSON_NO_SIZETYPEDEFINE
#endif

#include <rapidjson/document.h>

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

enum class MemberType { String, UInt16, StringArray };

// clang-format off
const std::unordered_map<std::string, MemberType> kRequiredMemberList = {
  { "server_address", MemberType::String },
  { "server_port", MemberType::UInt16 },
  { "group_list", MemberType::StringArray }
};
// clang-format on
} // namespace

struct ZeekConfiguration::PrivateData final {
  ConfigurationData config_data;
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
  return d->config_data.server_address;
}

std::uint16_t ZeekConfiguration::serverPort() const {
  return d->config_data.server_port;
}

const std::vector<std::string>& ZeekConfiguration::groupList() const {
  return d->config_data.group_list;
}

osquery::Status ZeekConfiguration::parseConfigurationData(
    ConfigurationData& config, const std::string& json) {
  config = {};

  rapidjson::Document document;
  document.Parse(json);
  if (!document.IsObject()) {
    return osquery::Status::failure(
        "The configuration file does not contain a valid JSON object");
  }

  for (const auto& p : kRequiredMemberList) {
    const auto& member_name = p.first;
    const auto& member_type = p.second;

    if (!document.HasMember(member_name)) {
      return osquery::Status::failure("The " + member_name +
                                      " member is required");
    }

    bool valid_type = false;
    const auto& member = document[member_name];

    switch (member_type) {
    case MemberType::String: {
      valid_type = member.IsString();
      break;
    }

    case MemberType::UInt16: {
      if (!member.IsNumber()) {
        break;
      }

      auto value = member.GetInt();
      if (value < 0 || value > std::numeric_limits<std::uint16_t>::max()) {
        break;
      }

      valid_type = true;
      break;
    }

    case MemberType::StringArray: {
      if (!member.IsArray()) {
        break;
      }

      for (auto i = 0; i < member.Size(); ++i) {
        if (!member[i].IsString()) {
          break;
        }
      }

      valid_type = true;
      break;
    }
    }

    if (!valid_type) {
      std::stringstream error_message;
      error_message << "The type of the " << member_name
                    << " setting should be: ";
      switch (member_type) {
      case MemberType::String: {
        error_message << "string";
        break;
      }

      case MemberType::UInt16: {
        error_message << "uint16";
        break;
      }

      case MemberType::StringArray: {
        error_message << "string array";
        break;
      }
      }

      return osquery::Status::failure(error_message.str());
    }
  }

  config.server_address = document["server_address"].GetString();
  config.server_port =
      static_cast<std::uint16_t>(document["server_port"].GetInt());

  const auto& group_list = document["group_list"];
  for (auto i = 0; i < group_list.Size(); ++i) {
    const auto& group = group_list[i].GetString();
    config.group_list.push_back(group);
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
    auto status = parseConfigurationData(d->config_data, sstream.str());
    if (status.ok()) {
      use_default_settings = false;

    } else {
      LOG(ERROR) << "Failed to parse the configuration file: "
                 << status.getMessage();
    }
  }

  if (use_default_settings) {
    LOG(WARNING) << "Using default configuration settings";

    d->config_data.server_address = kDefaultServerAddress;
    d->config_data.server_port = kDefaultServerPort;
    d->config_data.group_list = kDefaultGroupList;
  }

  VLOG(1) << "Zeek server address: " << d->config_data.server_address << ":"
          << d->config_data.server_port;

  std::stringstream group_list;
  for (const auto& group : d->config_data.group_list) {
    if (!group_list.str().empty()) {
      group_list << ", ";
    }

    group_list << group;
  }

  VLOG(1) << "Zeel group list: " << group_list.str();
}
} // namespace zeek