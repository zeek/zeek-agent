#include "virtualdatabase.h"
#include "sqlite_utils.h"
#include "virtualtablemodule.h"

#include <unordered_map>
#include <unordered_set>

#include <sqlite3.h>

namespace zeek {
struct VirtualDatabase::PrivateData final {
  sqlite3 *sqlite_database{nullptr};

  std::unordered_map<std::string, VirtualTableModule::Ref>
      registered_module_list;
};

VirtualDatabase::~VirtualDatabase() {
  sqlite3_close(d->sqlite_database);
  d->sqlite_database = nullptr;
}

Status VirtualDatabase::registerTable(IVirtualTable::Ref table) {
  if (d->registered_module_list.count(table->name()) != 0U) {
    return Status::failure("A table with the same is already registered");
  }

  auto status = validateTableSchema(table->schema());
  if (!status.succeeded()) {
    return status;
  }

  VirtualTableModule::Ref virtual_table_module;
  status = VirtualTableModule::create(virtual_table_module, std::move(table));

  if (!status.succeeded()) {
    return status;
  }

  table = {};

  auto err = sqlite3_create_module_v2(d->sqlite_database,
                                      virtual_table_module->name().c_str(),
                                      virtual_table_module->sqliteModule(),
                                      virtual_table_module.get(), nullptr);

  if (err != SQLITE_OK) {
    return Status::failure(
        "Failed to create the SQLite module for the virtual table");
  }

  auto table_name = virtual_table_module->name();

  d->registered_module_list.insert(
      {table_name, std::move(virtual_table_module)});

  return Status::success();
}

Status VirtualDatabase::query(IVirtualTable::RowList &row_list,
                              const std::string &query) const {
  row_list = {};

  SqliteStatement sql_stmt;
  auto status = prepareSqliteStatement(sql_stmt, d->sqlite_database, query);
  if (!status.succeeded()) {
    return status;
  }

  if (!status.succeeded()) {
    return status;
  }

  IVirtualTable::RowList output;
  auto column_count = sqlite3_column_count(sql_stmt.get());

  while (sqlite3_step(sql_stmt.get()) == SQLITE_ROW) {
    IVirtualTable::Row current_row = {};

    for (int column_index = 0; column_index < column_count; ++column_index) {
      auto sqlite_type = sqlite3_column_type(sql_stmt.get(), column_index);

      IVirtualTable::Value value = {};

      switch (sqlite_type) {
      case SQLITE_INTEGER:
        value.type = IVirtualTable::Value::ColumnType::Integer;

        value.data = static_cast<std::int64_t>(
            sqlite3_column_int(sql_stmt.get(), column_index));

        break;

      case SQLITE_TEXT: {
        value.type = IVirtualTable::Value::ColumnType::String;

        auto string_data = reinterpret_cast<const char *>(
            sqlite3_column_text(sql_stmt.get(), column_index));

        value.data = string_data;

        break;
      }

      default:
        return Status::failure("Invalid column type found");
      }

      auto column_name = sqlite3_column_name(sql_stmt.get(), column_index);
      current_row.insert({column_name, std::move(value)});
    }

    output.push_back(std::move(current_row));
  }

  row_list = std::move(output);
  output = {};

  return Status::success();
}

VirtualDatabase::VirtualDatabase() : d(new PrivateData) {
  if (sqlite3_open(":memory:", &d->sqlite_database) != SQLITE_OK) {
    throw Status::failure("Failed to create the SQLite database");
  }
}

Status VirtualDatabase::validateTableName(const std::string &name) {
  return validateSqliteName(name);
}

Status
VirtualDatabase::validateTableSchema(const IVirtualTable::Schema &schema) {
  static const std::unordered_set<IVirtualTable::Value::ColumnType>
      kValidColumnTypes = {IVirtualTable::Value::ColumnType::Integer,
                           IVirtualTable::Value::ColumnType::String};

  for (const auto &p : schema) {
    const auto &column_name = p.first;
    const auto &column_type = p.second;

    if (kValidColumnTypes.count(column_type) == 0U) {
      return Status::failure("Invalid column type encountered");
    }

    auto status = validateSqliteName(column_name);
    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}

Status IVirtualDatabase::create(IVirtualDatabase::Ref &obj) {
  obj.reset();

  try {
    auto ptr = new VirtualDatabase;
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
