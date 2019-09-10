/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include <osquery/status.h>

namespace zeek {
class ZeekConfiguration final {
 public:
  using Ref = std::unique_ptr<ZeekConfiguration>;
  static osquery::Status create(Ref& ref, const std::string& path);

  ~ZeekConfiguration();

  const std::string& serverAddress() const;
  std::uint16_t serverPort() const;
  const std::vector<std::string>& groupList() const;

  const std::string& certificateAuthority() const;
  const std::string& clientCertificate() const;
  const std::string& clientKey() const;

  struct Context final {
    std::string server_address;
    std::uint16_t server_port;
    std::vector<std::string> group_list;
    std::string certificate_authority;
    std::string client_certificate;
    std::string client_key;
  };

  static osquery::Status parseConfigurationData(Context& context,
                                                const std::string& json);

  ZeekConfiguration(const ZeekConfiguration&) = delete;
  ZeekConfiguration& operator=(const ZeekConfiguration&) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ZeekConfiguration(const std::string& path);
};
} // namespace zeek