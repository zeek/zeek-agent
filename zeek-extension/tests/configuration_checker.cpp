/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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

  // clang-format off
  const ConfigurationChecker::Constraints kRootItemsConstraintSet = {
    {
      "test_item1",

      {
        ConfigurationChecker::MemberConstraint::Type::String,
        false,
        "",
        true
      }
    },

    {
      "test_item2",

      {
        ConfigurationChecker::MemberConstraint::Type::UInt16,
        false,
        "",
        true
      }
    },
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

  const std::string kInvalidIntegerJson = R""(
    {
      "container01": {
        "string": "hello!"
      },

      "container02": {
        "number": 80000
      }
    }
  )"";

  document.Parse(kInvalidIntegerJson);
  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);

  ASSERT_FALSE(status.ok()) << status.getMessage();

  const std::string kRootItemsJson = R""(
    {
      "test_item1": "hello",
      "test_item2": 12345
    }
  )"";

  document.Parse(kRootItemsJson);
  status = ConfigurationChecker::validateWithConstraints(
      kRootItemsConstraintSet, document);

  ASSERT_TRUE(status.ok()) << status.getMessage();
}

} // namespace zeek
