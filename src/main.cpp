#include "dummytable.h"

#include <iostream>

#include <zeek/ivirtualdatabase.h>

int main() {
  zeek::IVirtualDatabase::Ref virtual_database;
  auto status = zeek::IVirtualDatabase::create(virtual_database);
  if (!status.succeeded()) {
    std::cerr << "Failed to create the virtual database: " << status.message()
              << "\n";
    return 1;
  }

  std::cout << "Virtual database created correctly\n";

  {
    zeek::DummyTable::Ref dummy_table;
    status = zeek::DummyTable::create(dummy_table);
    if (!status.succeeded()) {
      std::cerr << "Failed to create the table: " << status.message() << "\n";
      return 1;
    }

    std::cout << "Virtual table created correctly\n";

    status = virtual_database->registerTable(std::move(dummy_table));
    if (!status.succeeded()) {
      std::cerr << "Failed to register the virtual table: " << status.message()
                << "\n";

      return 1;
    }

    std::cout << "Virtual table successfully registered\n";
  }

  zeek::IVirtualTable::RowList row_list;
  status = virtual_database->query(row_list, "SELECT * FROM dummy_table");
  if (!status.succeeded()) {
    std::cerr << "Failed to query the database: " << status.message() << "\n";
    return 1;
  }

  std::cout << "Query result:\n";
  for (const auto &current_row : row_list) {
    for (const auto &p : current_row) {
      const auto &column_name = p.first;
      const auto &column_value = p.second;

      std::cout << column_name << ": ";

      switch (column_value.type) {
      case zeek::IVirtualTable::Value::ColumnType::Integer:
        std::cout << std::get<0>(column_value.data);
        break;

      case zeek::IVirtualTable::Value::ColumnType::String:
        std::cout << std::get<1>(column_value.data);
        break;

      default:
        std::cout << "<INVALID TYPE>";
        break;
      }

      std::cout << " ";
    }

    std::cout << "\n";
  }

  return 0;
}
