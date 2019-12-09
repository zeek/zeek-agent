#include "configurationchecker.h"

#include <rapidjson/pointer.h>

namespace zeek {
struct ConfigurationChecker::PrivateData final {
  Constraints constraints;
};

Status ConfigurationChecker::create(Ref &ref, const Constraints &constraints) {

  try {
    ref.reset();

    auto ptr = new ConfigurationChecker(constraints);
    ref.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ConfigurationChecker::~ConfigurationChecker() {}

Status
ConfigurationChecker::validate(const rapidjson::Document &document) const {

  return validateWithConstraints(d->constraints, document);
}

Status ConfigurationChecker::validateWithConstraints(
    const Constraints &constraints, const rapidjson::Document &document) {

  if (document.HasParseError() || !document.IsObject()) {
    return Status::failure(
        "The configuration file does not contain a valid JSON object");
  }

  for (const auto &p : constraints) {
    const auto &member_name = p.first;
    const auto &member_constraint = p.second;

    std::string member_path = "/" + member_constraint.path;
    if (member_path.size() > 1U) {
      member_path += "/";
    }

    member_path += member_name;

    rapidjson::Pointer member_pointer(member_path.c_str());
    auto member_ptr = rapidjson::GetValueByPointer(document, member_pointer);

    if (member_ptr == nullptr) {
      if (member_constraint.required) {
        return Status::failure("Required field is missing: " + member_name);
      }

      continue;
    }

    if (member_ptr->IsArray() != member_constraint.array) {
      return Status::failure("Required field array type mismatch: " +
                             member_name);
    }

    bool valid_type = false;

    switch (member_constraint.type) {
    case MemberConstraint::Type::String: {
      if (member_constraint.array) {
        for (auto i = 0U; i < member_ptr->Size(); ++i) {
          if (!(*member_ptr)[i].IsString()) {
            break;
          }
        }

        valid_type = true;

      } else {
        valid_type = member_ptr->IsString();
      }

      break;
    }

    case MemberConstraint::Type::UInt16:
    case MemberConstraint::Type::UInt32: {
      if (member_constraint.array) {
        for (auto i = 0U; i < member_ptr->Size(); ++i) {
          const auto &current_entry = (*member_ptr)[i];
          if (!current_entry.IsInt()) {
            break;
          }

          auto value = current_entry.GetInt64();
          if (value < 0) {
            break;
          }

          bool invalid_value{true};
          if (member_constraint.type == MemberConstraint::Type::UInt16) {
            invalid_value = (value > std::numeric_limits<std::uint16_t>::max());
          } else {
            invalid_value = (value > std::numeric_limits<std::uint32_t>::max());
          }

          if (invalid_value) {
            break;
          }
        }

        valid_type = true;

      } else {
        if (!member_ptr->IsInt()) {
          break;
        }

        auto value = member_ptr->GetInt64();
        if (value < 0) {
          break;
        }

        bool invalid_value{true};
        if (member_constraint.type == MemberConstraint::Type::UInt16) {
          invalid_value = (value > std::numeric_limits<std::uint16_t>::max());
        } else {
          invalid_value = (value > std::numeric_limits<std::uint32_t>::max());
        }

        if (invalid_value) {
          break;
        }

        valid_type = true;
      }
    }

    default: { break; }
    }

    if (!valid_type) {
      return Status::failure("The following field has an invalid type: " +
                             member_name);
    }
  }

  return Status::success();
}

ConfigurationChecker::ConfigurationChecker(const Constraints &constraints)
    : d(new PrivateData) {

  d->constraints = constraints;
}
} // namespace zeek
