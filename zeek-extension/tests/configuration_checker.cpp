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
#include <gtest/gtest.h>

namespace zeek {
TEST(ConfigurationChecker, validateWithConstraints) {
  // clang-format off
  const ConfigurationChecker::Constraints kSimpleConstraintSet = {
    {
      "string",

      {
        ConfigurationChecker::MemberConstraint::Type::String,
        false,
        "container01",
        true
      }
    },

    {
      "number",

      {
        ConfigurationChecker::MemberConstraint::Type::UInt16,
        false,
        "container02",
        true
      }
    }
  };
  // clang-format on

  // clang-format off
  const ConfigurationChecker::Constraints kArrayConstraintSet = {
    {
      "string",

      {
        ConfigurationChecker::MemberConstraint::Type::String,
        true,
        "container01",
        true
      }
    },

    {
      "number",

      {
        ConfigurationChecker::MemberConstraint::Type::UInt16,
        true,
        "container02",
        true
      }
    }
  };
  // clang-format on

  // clang-format off
  const ConfigurationChecker::Constraints kOptionalConstraintSet = {
    {
      "string",

      {
        ConfigurationChecker::MemberConstraint::Type::String,
        false,
        "",
        false
      }
    }
  };
  // clang-format on

  rapidjson::Document document;

  document.Parse("[]");
  auto status = ConfigurationChecker::validateWithConstraints(
      kSimpleConstraintSet, document);
  ASSERT_FALSE(status.ok()) << status.getMessage();

  document.Parse("...");
  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);
  ASSERT_FALSE(status.ok()) << status.getMessage();

  document.Parse("{}");
  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);
  ASSERT_FALSE(status.ok()) << status.getMessage();

  document.Parse("{}");
  status = ConfigurationChecker::validateWithConstraints(kOptionalConstraintSet,
                                                         document);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  const std::string kSimpleJson = R""(
    {
      "container01": {
        "string": "hello!"
      },

      "container02": {
        "number": 1
      }
    }
  )"";

  document.Parse(kSimpleJson);
  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  status = ConfigurationChecker::validateWithConstraints(kArrayConstraintSet,
                                                         document);
  ASSERT_FALSE(status.ok()) << status.getMessage();

  const std::string kArrayJson = R""(
    {
      "container01": {
        "string": [
          "hello",
          " ",
          "world!"
        ]
      },

      "container02": {
        "number": [
          1,
          2,
          3
        ]
      }
    }
  )"";

  document.Parse(kArrayJson);
  status = ConfigurationChecker::validateWithConstraints(kArrayConstraintSet,
                                                         document);
  ASSERT_TRUE(status.ok()) << status.getMessage();

  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);
  ASSERT_FALSE(status.ok()) << status.getMessage();
}

} // namespace zeek
