#include "utils.h"

#include <iostream>

#include <osquery/sdk/sdk.h>
#include <osquery/system.h>

namespace zeek {
Status getOsqueryTableList(std::vector<std::string> &table_list) {
  table_list.clear();

  auto osquery_registry = osquery::SQL::selectAllFrom("osquery_registry");

  for (const auto &row : osquery_registry) {
    auto registry_it = row.find("registry");
    if (registry_it == row.end()) {
      continue;
    }

    const auto &registry = registry_it->second;
    if (registry != "table") {
      continue;
    }

    auto name_it = row.find("name");
    if (name_it == row.end()) {
      continue;
    }

    const auto &name = name_it->second;
    table_list.push_back(name);
  }

  if (table_list.empty()) {
    return Status::failure("No tables found");
  }

  return Status::success();
}

Status getOsqueryTableSchema(IVirtualTable::Schema &table_schema,
                             const std::string &table_name) {
  table_schema.clear();

  osquery::PluginResponse response;
  auto osquery_status = osquery::Registry::call(
      "table", table_name, {{"action", "columns"}}, response);
  if (!osquery_status.ok()) {
    return Status::failure(osquery_status.getMessage());
  }

  IVirtualTable::Schema schema;

  for (const auto &column : response) {
    auto id_it = column.find("id");
    if (id_it == column.end()) {
      continue;
    }

    const auto &id = id_it->second;
    if (id != "column") {
      continue;
    }

    auto name_it = column.find("name");
    if (name_it == column.end()) {
      continue;
    }

    const auto &name = name_it->second;

    auto type_it = column.find("type");
    if (type_it == column.end()) {
      continue;
    }

    const auto &type = type_it->second;

    IVirtualTable::ColumnType column_type;

    if (type == "UNKNOWN") {
      return Status::failure("Invalid column type: " + type);

    } else if (type == "TEXT") {
      column_type = IVirtualTable::ColumnType::String;

    } else if (type == "INTEGER" || type == "BIGINT" ||
               type == "UNSIGNED BIGINT") {
      column_type = IVirtualTable::ColumnType::Integer;

    } else if (type == "DOUBLE") {
      column_type = IVirtualTable::ColumnType::Double;

    } else {
      return Status::failure("Unsupported column type: " + type);
    }

    schema.insert({name, column_type});
  }

  table_schema = std::move(schema);
  return Status::success();
}
} // namespace zeek
