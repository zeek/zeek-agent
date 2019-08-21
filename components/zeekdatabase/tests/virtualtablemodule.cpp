#include "virtualtablemodule.h"
#include "testtable.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("Basic VirtualTableModule operations", "[VirtualTableModule]") {
  GIVEN("a valid virtual table object") {
    IVirtualTable::Ref test_table(new TestTable(TestTable::SchemaType::Valid));

    WHEN("describing the virtual table schema") {
      std::string sql_statement;
      auto status = VirtualTableModule::generateSQLTableDefinition(
          sql_statement, test_table);

      REQUIRE(status.succeeded());

      THEN("a valid SQL statement is generated") {
        static const std::string kExpectedSQLStatement{
            "CREATE TABLE TestTable (\n  string TEXT,\n  integer BIGINT\n)\n"};

        REQUIRE(sql_statement == kExpectedSQLStatement);
      }
    }
  }

  GIVEN("a virtual table object with an invalid schema") {
    IVirtualTable::Ref test_table(
        new TestTable(TestTable::SchemaType::Invalid));

    WHEN("describing the virtual table schema") {
      std::string sql_statement;
      auto status = VirtualTableModule::generateSQLTableDefinition(
          sql_statement, test_table);

      THEN("an error is returned") { REQUIRE(!status.succeeded()); }
    }
  }
}
} // namespace zeek
