#include "tables/audisp/socketeventstableplugin.h"

#include <mutex>

namespace zeek {
struct SocketEventsTablePlugin::PrivateData final {
  RowList row_list;
  std::mutex row_list_mutex;
};

Status SocketEventsTablePlugin::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new SocketEventsTablePlugin();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

SocketEventsTablePlugin::~SocketEventsTablePlugin() {}

const std::string &SocketEventsTablePlugin::name() const {
  static const std::string kTableName{"socket_events"};

  return kTableName;
}

const SocketEventsTablePlugin::Schema &SocketEventsTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "action", IVirtualTable::ColumnType::String },
    { "pid", IVirtualTable::ColumnType::Integer },
    { "path", IVirtualTable::ColumnType::String },
    { "fd", IVirtualTable::ColumnType::String },
    { "auid", IVirtualTable::ColumnType::Integer },
    { "success", IVirtualTable::ColumnType::Integer },
    { "family", IVirtualTable::ColumnType::Integer },
    { "local_address", IVirtualTable::ColumnType::String },
    { "remote_address", IVirtualTable::ColumnType::String },
    { "local_port", IVirtualTable::ColumnType::Integer },
    { "remote_port", IVirtualTable::ColumnType::Integer },
    { "time", IVirtualTable::ColumnType::Integer },
    { "uptime", IVirtualTable::ColumnType::Integer }
  };
  // clang-format on

  return kTableSchema;
}

Status SocketEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status SocketEventsTablePlugin::processEvents(
    const IAudispConsumer::AuditEventList &event_list) {
  RowList generated_row_list;

  for (const auto &audit_event : event_list) {
    Row row;

    auto status = generateRow(row, audit_event);
    if (!status.succeeded()) {
      return status;
    }

    if (!row.empty()) {
      generated_row_list.push_back(std::move(row));
    }
  }

  {
    std::lock_guard<std::mutex> lock(d->row_list_mutex);

    // clang-format off
    d->row_list.insert(
      d->row_list.end(),
      std::make_move_iterator(generated_row_list.begin()), 
      std::make_move_iterator(generated_row_list.end())
    );
    // clang-format on
  }

  return Status::success();
}

SocketEventsTablePlugin::SocketEventsTablePlugin() : d(new PrivateData) {}

Status SocketEventsTablePlugin::generateRow(
    Row &row, const IAudispConsumer::AuditEvent &audit_event) {
  row = {};

  if (!audit_event.syscall_data.succeeded) {
    return Status::success();
  }

  switch (audit_event.syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Bind:
  case IAudispConsumer::SyscallRecordData::Type::Connect:
    break;

  default:
    return Status::success();
  }

  return Status::success();
}
} // namespace zeek
