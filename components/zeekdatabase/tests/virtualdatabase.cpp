#include "virtualdatabase.h"
#include "testtable.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Basic VirtualDatabase operations", "[VirtualDatabase]") {
  GIVEN("a virtual database") {
    IVirtualDatabase::Ref virtual_database;
    auto status = IVirtualDatabase::create(virtual_database);
    REQUIRE(status.succeeded());

    WHEN("registering a new table plugin") {
      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid));

      status = virtual_database->registerTable(test_table);
      REQUIRE(status.succeeded());

      THEN("the new virtual table can be queried") {
        IVirtualTable::RowList row_list;
        auto status =
            virtual_database->query(row_list, "SELECT * FROM TestTable;");

        REQUIRE(status.succeeded());
        REQUIRE(!row_list.empty());
      }
    }

    WHEN("registering the same table twice") {
      Status status;

      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid));

      status = virtual_database->registerTable(test_table);

      REQUIRE(status.succeeded());

      {
        IVirtualTable::Ref test_table(
            new TestTable(TestTable::SchemaType::Valid));

        status = virtual_database->registerTable(test_table);
      }

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }

    WHEN("registering a table with an invalid schema") {
      Status status;

      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Invalid));

      status = virtual_database->registerTable(test_table);

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }

    WHEN("querying an invalid table") {
      IVirtualTable::RowList row_list;

      // clang-format off
      row_list.push_back(
        {
          { "dummy_value", "dummy_value" },
          { "dummy_value2", "dummy_value2" }
        }
      );
      // clang-format on

      auto status =
          virtual_database->query(row_list, "SELECT * FROM InvalidTableName;");

      THEN("an error is generated and no results are returned") {
        REQUIRE(!status.succeeded());
        REQUIRE(row_list.empty());
      }
    }

    WHEN("querying a table with multiple rows") {
      static const std::size_t kRowCount{100U};

      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid, kRowCount));

      auto status = virtual_database->registerTable(test_table);
      REQUIRE(status.succeeded());

      IVirtualTable::RowList row_list;
      status = virtual_database->query(row_list, "SELECT * FROM TestTable;");

      THEN("the correct rows are returned") {
        REQUIRE(status.succeeded());
        REQUIRE(row_list.size() == kRowCount);

        for (std::size_t i = 0U; i < row_list.size(); ++i) {
          const auto &current_row = row_list.at(i);

          auto integer_field_it = current_row.find("integer");
          REQUIRE(integer_field_it != current_row.end());

          auto string_field_it = current_row.find("string");
          REQUIRE(string_field_it != current_row.end());

          const auto &integer_optional = integer_field_it->second;
          REQUIRE(integer_optional.has_value());

          const auto &string_optional = string_field_it->second;
          REQUIRE(string_optional.has_value());

          const auto &integer_variant = integer_optional.value();
          REQUIRE(integer_variant.index() == 0U);

          const auto &string_variant = string_optional.value();
          REQUIRE(string_variant.index() == 1U);

          const auto &integer_value = std::get<0U>(integer_variant);
          CHECK(integer_value == i);

          const auto &string_value = std::get<1U>(string_variant);
          CHECK(string_value == std::to_string(i));
        }
      }
    }

    WHEN("querying an empty table") {
      static const std::size_t kRowCount{0U};

      IVirtualTable::Ref test_table(
          new TestTable(TestTable::SchemaType::Valid, kRowCount));

      auto status = virtual_database->registerTable(test_table);
      REQUIRE(status.succeeded());

      IVirtualTable::RowList row_list;

      status = virtual_database->query(row_list, "SELECT * FROM TestTable;");

      THEN("no rows are returned") {
        REQUIRE(status.succeeded());
        REQUIRE(row_list.size() == kRowCount);
      }
    }
  }
}

SCENARIO("VirtualDatabase utilities", "[VirtualDatabase]") {
  GIVEN("an invalid schema") {
    TestTable invalid_table(TestTable::SchemaType::Invalid);

    WHEN("validating column types and names") {
      auto status =
          VirtualDatabase::validateTableSchema(invalid_table.schema());

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }
  }

  GIVEN("a valid schema") {
    TestTable valid_table(TestTable::SchemaType::Valid);

    WHEN("validating column types and names") {
      auto status = VirtualDatabase::validateTableSchema(valid_table.schema());

      THEN("success is returned") { REQUIRE(status.succeeded()); }
    }
  }

  GIVEN("an invalid table name") {
    static const std::vector<std::string> kInvalidTableNameList = {
        "", "0_invalid_name", "invalid name"};

    WHEN("validating the name") {
      std::vector<Status> status_list;

      for (const auto &table_name : kInvalidTableNameList) {
        auto status = VirtualDatabase::validateTableName(table_name);
        status_list.push_back(status);
      }

      THEN("the name is rejected") {
        for (const auto &status : status_list) {
          REQUIRE(!status.succeeded());
        }
      }
    }
  }
}
} // namespace zeek
