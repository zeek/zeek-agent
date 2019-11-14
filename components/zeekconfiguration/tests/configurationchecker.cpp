#include "configurationchecker.h"

#include <catch2/catch.hpp>

namespace zeek {
TEST_CASE("Checking configuration files with constraints",
          "[ConfigurationChecker]") {
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

  REQUIRE(!status.succeeded());

  document.Parse("...");
  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);

  REQUIRE(!status.succeeded());

  document.Parse("{}");
  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);

  REQUIRE(!status.succeeded());

  document.Parse("{}");
  status = ConfigurationChecker::validateWithConstraints(kOptionalConstraintSet,
                                                         document);

  REQUIRE(status.succeeded());

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

  REQUIRE(status.succeeded());

  status = ConfigurationChecker::validateWithConstraints(kArrayConstraintSet,
                                                         document);

  REQUIRE(!status.succeeded());

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

  REQUIRE(status.succeeded());

  status = ConfigurationChecker::validateWithConstraints(kSimpleConstraintSet,
                                                         document);

  REQUIRE(!status.succeeded());

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

  REQUIRE(!status.succeeded());

  const std::string kRootItemsJson = R""(
    {
      "test_item1": "hello",
      "test_item2": 12345
    }
  )"";

  document.Parse(kRootItemsJson);
  status = ConfigurationChecker::validateWithConstraints(
      kRootItemsConstraintSet, document);

  REQUIRE(status.succeeded());
}
} // namespace zeek
