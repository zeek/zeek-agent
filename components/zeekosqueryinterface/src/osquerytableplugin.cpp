#include "osquerytableplugin.h"
#include "utils.h"

#include <osquery/sdk/sdk.h>
#include <osquery/system.h>

namespace zeek {
struct OsqueryTablePlugin::PrivateData final {
  PrivateData(IZeekLogger &logger_) : logger(logger_) {}

  std::string table_name;
  Schema table_schema;
  IZeekLogger &logger;
};

Status OsqueryTablePlugin::create(Ref &ref,
                                  const std::string &osquery_table_name,
                                  IZeekLogger &logger) {
  try {
    ref.reset();

    auto ptr = new OsqueryTablePlugin(osquery_table_name, logger);
    ref.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

OsqueryTablePlugin::~OsqueryTablePlugin() {}

const std::string &OsqueryTablePlugin::name() const { return d->table_name; }

const IVirtualTable::Schema &OsqueryTablePlugin::schema() const {
  return d->table_schema;
}

Status OsqueryTablePlugin::generateRowList(RowList &row_list) {
  row_list = {};

  // Forward the SELECT to osquery
  osquery::PluginResponse response;
  auto osquery_status = osquery::Registry::call(
      "table", d->table_name, {{"action", "generate"}}, response);

  if (!osquery_status.ok()) {
    return Status::failure(osquery_status.getMessage());
  }

  for (const auto &row : response) {
    Row current_row = {};

    for (const auto &column : row) {
      const auto &column_name = column.first;
      const auto &column_value = column.second;

      auto column_info_it = d->table_schema.find(column_name);
      if (column_info_it == d->table_schema.end()) {
        d->logger.logMessage(IZeekLogger::Severity::Error,
                             "Unknown column returned from table " +
                                 d->table_name + ": " + column_name);

        continue;
      }

      const auto &column_type = column_info_it->second;

      switch (column_type) {
      case IVirtualTable::ColumnType::Integer: {
        auto converted_value = static_cast<std::int64_t>(
            std::strtoll(column_value.c_str(), nullptr, 10));

        current_row.insert({column_name, converted_value});
        break;
      }

      case IVirtualTable::ColumnType::String: {
        current_row.insert({column_name, column_value});
        break;
      }

      case IVirtualTable::ColumnType::Double: {
        auto converted_value = std::stod(column_value.c_str(), nullptr);

        current_row.insert({column_name, converted_value});
        break;
      }

      default: {
        std::string message{"Unknown column type in schema for table " +
                            d->table_name + " (" + column_name + ")"};
        d->logger.logMessage(IZeekLogger::Severity::Error, message);
        return Status::failure(message);
      }
      }
    }

    row_list.push_back(std::move(current_row));
  }

  // osquery may have not returned all the columns we wanted; our virtual table
  // module will catch this error, so make sure the rows are correct

  for (auto &row : row_list) {
    for (const auto &expected_column : d->table_schema) {
      const auto &expected_column_name = expected_column.first;

      if (row.count(expected_column_name) > 0) {
        continue;
      }

      const auto &expected_column_type = expected_column.second;

      switch (expected_column_type) {
      case IVirtualTable::ColumnType::Integer: {
        row.insert({expected_column_name, static_cast<std::int64_t>(0)});
        break;
      }

      case IVirtualTable::ColumnType::String: {
        row.insert({expected_column_name, ""});
        break;
      }

      case IVirtualTable::ColumnType::Double: {
        row.insert({expected_column_name, 0.0});
        break;
      }

      default: {
        std::string message{"Unknown column type in schema for table " +
                            d->table_name + " (" + expected_column_name + ")"};
        d->logger.logMessage(IZeekLogger::Severity::Error, message);
        return Status::failure(message);
      }
      }
    }
  }

  return Status::success();
}

OsqueryTablePlugin::OsqueryTablePlugin(const std::string &osquery_table_name,
                                       IZeekLogger &logger)
    : d(new PrivateData(logger)) {
  d->table_name = osquery_table_name;

  auto status = getOsqueryTableSchema(d->table_schema, d->table_name);
  if (!status.succeeded()) {
    throw status;
  }
}
} // namespace zeek
