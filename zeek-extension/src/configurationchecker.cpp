/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "configurationchecker.h"

#include <rapidjson/pointer.h>

namespace zeek {
struct ConfigurationChecker::PrivateData final {
  Constraints constraints;
};

osquery::Status ConfigurationChecker::create(Ref& ref,
                                             const Constraints& constraints) {
  try {
    ref.reset();

    auto ptr = new ConfigurationChecker(constraints);
    ref.reset(ptr);

    return osquery::Status::success();

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Memory allocation failure");

  } catch (const osquery::Status& status) {
    return status;
  }
}

ConfigurationChecker::~ConfigurationChecker() {}

osquery::Status ConfigurationChecker::validate(
    const rapidjson::Document& document) const {
  return validateWithConstraints(d->constraints, document);
}

osquery::Status ConfigurationChecker::validateWithConstraints(
    const Constraints& constraints, const rapidjson::Document& document) {
  if (document.HasParseError() || !document.IsObject()) {
    return osquery::Status::failure(
        "The configuration file does not contain a valid JSON object");
  }

  for (const auto& p : constraints) {
    const auto& member_name = p.first;
    const auto& member_constraint = p.second;

    std::string member_path = "/" + member_constraint.path;
    if (member_path.size() > 1U) {
      member_path += "/";
    }

    member_path += member_name;

    rapidjson::Pointer member_pointer(member_path);
    auto member_ptr = rapidjson::GetValueByPointer(document, member_pointer);

    if (member_ptr == nullptr) {
      if (member_constraint.required) {
        return osquery::Status::failure("Required field is missing: " +
                                        member_name);
      }

      continue;
    }

    if (member_ptr->IsArray() != member_constraint.array) {
      return osquery::Status::failure("Required field array type mismatch: " +
                                      member_name);
    }

    bool valid_type = false;

    switch (member_constraint.type) {
    case MemberConstraint::Type::String: {
      if (member_constraint.array) {
        for (auto i = 0; i < member_ptr->Size(); ++i) {
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

    case MemberConstraint::Type::UInt16: {
      if (member_constraint.array) {
        for (auto i = 0; i < member_ptr->Size(); ++i) {
          if (!(*member_ptr)[i].IsInt()) {
            break;
          }

          auto value = member_ptr->GetInt();
          if (value < 0 || value > std::numeric_limits<std::uint16_t>::max()) {
            break;
          }
        }

        valid_type = true;

      } else {
        if (!member_ptr->IsInt()) {
          break;
        }

        auto value = member_ptr->GetInt();
        if (value < 0 || value > std::numeric_limits<std::uint16_t>::max()) {
          break;
        }

        valid_type = true;
      }
    }

    default: { break; }
    }

    if (!valid_type) {
      return osquery::Status::failure(
          "The following field has an invalid type: " + member_name);
    }
  }

  return osquery::Status::success();
}

ConfigurationChecker::ConfigurationChecker(const Constraints& constraints)
    : d(new PrivateData) {
  d->constraints = constraints;
}
} // namespace zeek
