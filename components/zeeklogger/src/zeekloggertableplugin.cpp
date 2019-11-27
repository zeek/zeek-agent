#include "zeekloggertableplugin.h"

#include <chrono>
#include <mutex>

namespace zeek {
struct ZeekLoggerTablePlugin::PrivateData final {
  RowList row_list;
  std::mutex row_list_mutex;
};

Status ZeekLoggerTablePlugin::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new ZeekLoggerTablePlugin();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekLoggerTablePlugin::~ZeekLoggerTablePlugin() {}

const std::string &ZeekLoggerTablePlugin::name() const {
  static const std::string kTableName{"zeek_logger"};

  return kTableName;
}

const ZeekLoggerTablePlugin::Schema &ZeekLoggerTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "time", IVirtualTable::ColumnType::Integer },
    { "severity", IVirtualTable::ColumnType::String },
    { "message", IVirtualTable::ColumnType::String },
  };
  // clang-format on

  return kTableSchema;
}

Status ZeekLoggerTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status ZeekLoggerTablePlugin::appendMessage(IZeekLogger::Severity severity,
                                            const std::string &message) {

  Row row;
  auto status = generateRow(row, severity, message);
  if (!status.succeeded()) {
    return status;
  }

  {
    std::lock_guard<std::mutex> lock(d->row_list_mutex);

    d->row_list.push_back(std::move(row));
  }

  return Status::success();
}

ZeekLoggerTablePlugin::ZeekLoggerTablePlugin() : d(new PrivateData) {}

Status ZeekLoggerTablePlugin::generateRow(Row &row,
                                          IZeekLogger::Severity severity,
                                          const std::string &message) {

  row = {};

  std::string severity_name;

  switch (severity) {
  case IZeekLogger::Severity::Debug:
    severity_name = "Debug";
    break;

  case IZeekLogger::Severity::Information:
    severity_name = "Information";
    break;

  case IZeekLogger::Severity::Warning:
    severity_name = "Warning";
    break;

  case IZeekLogger::Severity::Error:
    severity_name = "Error";
    break;

  default:
    return Status::failure("Invalid severity specified");
  }

  auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());

  row["time"] = current_timestamp.count();
  row["severity"] = severity_name;
  row["message"] = message;

  return Status::success();
}
} // namespace zeek
