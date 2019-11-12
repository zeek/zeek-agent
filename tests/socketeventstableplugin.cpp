#include "tables/audisp/socketeventstableplugin.h"
#include "utils.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Row generation in the socket_events table",
         "[SocketEventsTablePlugin]") {

  GIVEN("a valid connect audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kConnectAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Connect,
        0,
        38031,
        38030,
        true,
        1000,
        1000,
        1000,
        1000,
        1000,
        "/usr/bin/curl",
        "10"
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {
        {
          "AF_INET",
          443,
          "127.0.0.1"
        }
      }
    };
    // clang-format on

    WHEN("generating a table row") {
      IVirtualTable::Row row;
      auto status =
          SocketEventsTablePlugin::generateRow(row, kConnectAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        // clang-format off
        static ExpectedValueList kExpectedConnectColumnList = {
          { "action", "connect" },
          { "pid", 38031 },
          { "path", "/usr/bin/curl" },
          { "fd", 16 },
          { "auid", 1000 },
          { "success", "true" },
          { "family", "AF_INET" },
          { "local_address", { } },
          { "remote_address", "127.0.0.1" },
          { "local_port", { } },
          { "remote_port", 443 }
        };
        // clang-format on

        REQUIRE(row.size() == kExpectedConnectColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedConnectColumnList);
      }
    }
  }

  GIVEN("a valid bind audit event") {
    // clang-format off
    static const IAudispConsumer::AuditEvent kBindAuditEvent = {
      // Syscall record data
      {
        IAudispConsumer::SyscallRecordData::Type::Bind,
        0,
        38031,
        38030,
        true,
        1000,
        1000,
        1000,
        1000,
        1000,
        "/usr/bin/curl",
        "10"
      },

      // Execve record data
      { },

      // Path record data
      { },

      // Cwd data
      { },

      // Sockaddr data
      {
        {
          "AF_INET",
          8080,
          "0.0.0.0"
        }
      }
    };
    // clang-format on

    WHEN("generating table rows") {
      IVirtualTable::Row row;
      auto status = SocketEventsTablePlugin::generateRow(row, kBindAuditEvent);

      REQUIRE(status.succeeded());

      THEN("rows are generated correctly") {
        // clang-format off
        static ExpectedValueList kExpectedBindColumnList = {
          { "action", "bind" },
          { "pid", 38031 },
          { "path", "/usr/bin/curl" },
          { "fd", 16 },
          { "auid", 1000 },
          { "success", "true" },
          { "family", "AF_INET" },
          { "local_address", "0.0.0.0" },
          { "remote_address", { } },
          { "local_port", 8080 },
          { "remote_port", { } }
        };
        // clang-format on

        REQUIRE(row.size() == kExpectedBindColumnList.size() + 1);
        REQUIRE(row.count("time") != 0U);
        REQUIRE(row.at("time").has_value());

        validateRow(row, kExpectedBindColumnList);
      }
    }
  }
}
} // namespace zeek
