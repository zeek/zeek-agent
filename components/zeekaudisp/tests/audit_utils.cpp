#include "audit_utils.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Audit utilities", "[audit_utils]") {
  GIVEN("valid hex digits") {
    static const std::string kHexDigits{"0123456789ABCDEF"};

    WHEN("converting each digit to a byte value") {
      std::vector<char> byte_list;

      for (auto i = 0U; i < kHexDigits.size(); ++i) {
        char output_byte = {};

        auto status = convertHexDigitToByte(output_byte, kHexDigits.at(i));
        REQUIRE(status);

        byte_list.push_back(output_byte);
      }

      THEN("the digits are correctly decoded") {
        REQUIRE(byte_list.size() == kHexDigits.size());

        for (auto i = 0U; i < byte_list.size(); ++i) {
          REQUIRE(byte_list.at(i) == i);
        }
      }
    }
  }

  GIVEN("a valid hex string") {
    static const std::string kValidHexString01{"48656C6C6F205A65656B21"};
    static const std::string kValidHexStringContent01{"Hello Zeek!"};

    static const std::string kValidHexString02{""};
    static const std::string kValidHexStringContent02{""};

    WHEN("converting the buffer to text") {
      std::string output01;
      auto status01 = convertHexString(output01, kValidHexString01);

      std::string output02;
      auto status02 = convertHexString(output02, kValidHexString02);

      THEN("the content is correctly decoded") {
        REQUIRE(status01);
        REQUIRE(output01 == kValidHexStringContent01);

        REQUIRE(status02);
        REQUIRE(output02 == kValidHexStringContent02);
      }
    }
  }

  GIVEN("an invalid hex string") {
    static const std::string kInvalidHexString01{"48656C6C6F205A65656B2"};
    static const std::string kInvalidHexString02{"48656c6c6f205a65656b21"};
    static const std::string kInvalidHexString03{"HELLO!"};

    WHEN("converting the buffer to text") {
      std::string output01;
      auto status01 = convertHexString(output01, kInvalidHexString01);

      std::string output02;
      auto status02 = convertHexString(output02, kInvalidHexString02);

      std::string output03;
      auto status03 = convertHexString(output03, kInvalidHexString03);

      THEN("no output is generated") {
        REQUIRE(!status01);
        REQUIRE(output01.empty());

        REQUIRE(!status02);
        REQUIRE(output02.empty());

        REQUIRE(!status03);
        REQUIRE(output03.empty());
      }
    }
  }

  GIVEN("a valid audit string") {
    static const std::string kValidHexString01{"48656C6C6F205A65656B21"};
    static const std::string kValidHexStringContent01{"Hello Zeek!"};

    static const std::string kValidHexString02{"\"Hello Zeek!\""};
    static const std::string kValidHexStringContent02{"Hello Zeek!"};

    static const std::string kValidHexString03{"\"\""};
    static const std::string kValidHexStringContent03{""};

    WHEN("converting the string to text") {
      std::string output01;
      auto status01 = convertAuditString(output01, kValidHexString01);

      std::string output02;
      auto status02 = convertAuditString(output02, kValidHexString02);

      std::string output03;
      auto status03 = convertAuditString(output03, kValidHexString03);

      THEN("the correct output is generated") {
        REQUIRE(status01);
        REQUIRE(output01 == kValidHexStringContent01);

        REQUIRE(status02);
        REQUIRE(output02 == kValidHexStringContent02);

        REQUIRE(status03);
        REQUIRE(output03 == kValidHexStringContent03);
      }
    }
  }

  GIVEN("an invalid audit string") {
    static const std::string kInvalidHexString01{"123"};
    static const std::string kInvalidHexString02{"\""};
    static const std::string kInvalidHexString03{"HELLO!"};

    WHEN("converting the string to text") {
      std::string output01;
      auto status01 = convertAuditString(output01, kInvalidHexString01);

      std::string output02;
      auto status02 = convertAuditString(output02, kInvalidHexString02);

      std::string output03;
      auto status03 = convertAuditString(output03, kInvalidHexString03);

      THEN("no output is generated") {
        REQUIRE(!status01);
        REQUIRE(output01.empty());

        REQUIRE(!status02);
        REQUIRE(output02.empty());

        REQUIRE(!status03);
        REQUIRE(output03.empty());
      }
    }
  }
}
} // namespace zeek
