#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <rapidjson/document.h>

#include <zeek/status.h>

namespace zeek {
/// \brief Checks that a given JSON configuration is within the given
///        constraints
class ConfigurationChecker final {
public:
  /// \brief A single configuration field constraint
  struct MemberConstraint final {
    /// \brief Supported field types
    enum class Type { String, UInt16, UInt32 };

    /// \brief The expected field type
    Type type;

    /// \brief Whether the field is supposed to be an array or not
    bool array{false};

    /// \brief The field path (i.e. parent_object_name.field_name)
    std::string path;

    /// \brief Whether it is an error if this field is missing or not
    bool required{false};
  };

  /// \brief A list of constraints
  using Constraints = std::unordered_map<std::string, MemberConstraint>;

  /// \brief A reference to a configuration checker
  using Ref = std::unique_ptr<ConfigurationChecker>;

  /// \brief Factory method
  /// \param ref Where the created object is stored
  /// \param constraints A list of constraints to apply to the configuration
  ///                    file
  static Status create(Ref &ref, const Constraints &constraints);

  /// \brief Destructor
  ~ConfigurationChecker();

  /// \brief Validates the given rapidjson Document against the configured
  ///        constraints
  /// \param document The JSON, parsed by a rapidjson::Document
  ///                 object
  /// \return A Status object
  Status validate(const rapidjson::Document &document) const;

  /// \brief Validates the given rapidjson Document against the specified
  ///        constraints
  /// \param constraints The set of constraints
  /// \param document The JSON, parsed by a rapidjson::Document object
  /// \return A Status object
  static Status validateWithConstraints(const Constraints &constraints,
                                        const rapidjson::Document &document);

  ConfigurationChecker(const ConfigurationChecker &) = delete;
  ConfigurationChecker &operator=(const ConfigurationChecker &) = delete;

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Constructor
  /// \param constraints The list of configuration constraints
  ConfigurationChecker(const Constraints &constraints);
};
} // namespace zeek
