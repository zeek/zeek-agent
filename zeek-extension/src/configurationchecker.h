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

#include <string>
#include <unordered_map>
#include <vector>

// todo: replace this with <rapidjson/document.h> when moving to osquery 4.x
#include <osquery/core/json.h>
#include <osquery/status.h>

namespace zeek {
class ConfigurationChecker final {
 public:
  struct MemberConstraint final {
    enum class Type { String, UInt16 };

    Type type;
    bool array{false};
    std::string path;
    bool required{false};
  };

  using Constraints = std::unordered_map<std::string, MemberConstraint>;

  using Ref = std::unique_ptr<ConfigurationChecker>;
  static osquery::Status create(Ref& ref, const Constraints& constraints);

  ~ConfigurationChecker();

  osquery::Status validate(const rapidjson::Document& document) const;

  static osquery::Status validateWithConstraints(
      const Constraints& constraints, const rapidjson::Document& document);

  ConfigurationChecker(const ConfigurationChecker&) = delete;
  ConfigurationChecker& operator=(const ConfigurationChecker&) = delete;

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ConfigurationChecker(const Constraints& constraints);
};
} // namespace zeek
