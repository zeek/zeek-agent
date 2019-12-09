#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <rapidjson/document.h>

#include <zeek/status.h>

namespace zeek {
class ConfigurationChecker final {
public:
  struct MemberConstraint final {
    enum class Type { String, UInt16, UInt32 };

    Type type;
    bool array{false};
    std::string path;
    bool required{false};
  };

  using Constraints = std::unordered_map<std::string, MemberConstraint>;

  using Ref = std::unique_ptr<ConfigurationChecker>;
  static Status create(Ref &ref, const Constraints &constraints);

  ~ConfigurationChecker();

  Status validate(const rapidjson::Document &document) const;

  static Status validateWithConstraints(const Constraints &constraints,
                                        const rapidjson::Document &document);

  ConfigurationChecker(const ConfigurationChecker &) = delete;
  ConfigurationChecker &operator=(const ConfigurationChecker &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  ConfigurationChecker(const Constraints &constraints);
};
} // namespace zeek
