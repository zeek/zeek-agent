/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
