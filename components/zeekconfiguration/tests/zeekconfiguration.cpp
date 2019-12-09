#include "zeekconfiguration.h"

#include <catch2/catch.hpp>

namespace zeek {
TEST_CASE("Reading configuration files", "[ZeekConfiguration]") {
  const std::string kTestConfiguration = R""(
  {
    "server_address": "127.0.0.1",
    "server_port": 9999,

    "log_folder": "/var/log/zeek",

    "group_list": [
      "test/group/0",
      "test/group/1"
    ],

    "authentication": {
      "certificate_authority": "/dev/null",
      "client_certificate": "/dev/null",
      "client_key": "/dev/null"
    },

    "osquery_extensions_socket": "/test/path"
  }
  )"";

  ZeekConfiguration::Context context;
  auto status =
      ZeekConfiguration::parseConfigurationData(context, kTestConfiguration);
  REQUIRE(status.succeeded());

  REQUIRE(context.server_address == "127.0.0.1");
  REQUIRE(context.server_port == 9999U);

  REQUIRE(context.log_folder == "/var/log/zeek");

  REQUIRE(context.group_list.size() == 2U);
  REQUIRE(context.group_list.at(0U) == "test/group/0");
  REQUIRE(context.group_list.at(1U) == "test/group/1");

  REQUIRE(context.certificate_authority == "/dev/null");
  REQUIRE(context.client_certificate == "/dev/null");
  REQUIRE(context.client_key == "/dev/null");

#if defined(ZEEK_AGENT_ENABLE_OSQUERY_SUPPORT)
  REQUIRE(context.osquery_extensions_socket == "/test/path");
#else
  REQUIRE(context.osquery_extensions_socket == "");
#endif
}
} // namespace zeek
