#include "tables/audisp/processeventstableplugin.h"

#include <mutex>

namespace zeek {
struct ProcessEventsTablePlugin::PrivateData final {
  RowList row_list;
  std::mutex row_list_mutex;
};

Status ProcessEventsTablePlugin::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new ProcessEventsTablePlugin();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ProcessEventsTablePlugin::~ProcessEventsTablePlugin() {}

const std::string &ProcessEventsTablePlugin::name() const {
  static const std::string kTableName{"process_events"};

  return kTableName;
}

const ProcessEventsTablePlugin::Schema &
ProcessEventsTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    // Present in the AUDIT_SYSCALL record
    { "syscall", IVirtualTable::ColumnType::String },
    { "pid", IVirtualTable::ColumnType::Integer },
    { "parent", IVirtualTable::ColumnType::Integer },
    { "auid", IVirtualTable::ColumnType::Integer },
    { "uid", IVirtualTable::ColumnType::Integer },
    { "euid", IVirtualTable::ColumnType::Integer },
    { "gid", IVirtualTable::ColumnType::Integer },
    { "egid", IVirtualTable::ColumnType::Integer },
    { "owner_uid", IVirtualTable::ColumnType::Integer },
    { "owner_gid", IVirtualTable::ColumnType::Integer },

    // Present in the AUDIT_EXECVE record(s)
    { "argc", IVirtualTable::ColumnType::Integer },
    { "cmdline", IVirtualTable::ColumnType::String },

    // Present in the AUDIT_PATH record(s)
    { "path", IVirtualTable::ColumnType::String },
    { "mode", IVirtualTable::ColumnType::String },
    
    // Present in the AUDIT_CWD record
    { "cwd", IVirtualTable::ColumnType::String },
    
    // Custom
    { "time", IVirtualTable::ColumnType::Integer }
  };
  // clang-format on

  return kTableSchema;
}

Status ProcessEventsTablePlugin::generateRowList(RowList &row_list) {
  std::lock_guard<std::mutex> lock(d->row_list_mutex);

  row_list = std::move(d->row_list);
  d->row_list = {};

  return Status::success();
}

Status ProcessEventsTablePlugin::processEvents(
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

ProcessEventsTablePlugin::ProcessEventsTablePlugin() : d(new PrivateData) {}

Status ProcessEventsTablePlugin::generateRow(
    Row &row, const IAudispConsumer::AuditEvent &audit_event) {
  row = {};

  if (!audit_event.syscall_data.succeeded) {
    return Status::success();
  }

  const auto &syscall_data = audit_event.syscall_data;
  const char *syscall_name{nullptr};

  switch (syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Execve:
    syscall_name = "execve";
    break;

  case IAudispConsumer::SyscallRecordData::Type::ExecveAt:
    syscall_name = "execveat";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Fork:
    syscall_name = "fork";
    break;

  case IAudispConsumer::SyscallRecordData::Type::VFork:
    syscall_name = "vfork";
    break;

  case IAudispConsumer::SyscallRecordData::Type::Clone:
    syscall_name = "clone";
    break;

  default:
    return Status::success();
  }

  auto current_timestamp = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch());

  row["time"] = std::to_string(current_timestamp.count());
  row["syscall"] = syscall_name;
  row["pid"] = syscall_data.process_id;
  row["parent"] = syscall_data.parent_process_id;
  row["pid"] = syscall_data.process_id;
  row["auid"] = syscall_data.auid;
  row["uid"] = syscall_data.uid;
  row["euid"] = syscall_data.euid;
  row["gid"] = syscall_data.gid;
  row["egid"] = syscall_data.egid;

  if (syscall_data.type == IAudispConsumer::SyscallRecordData::Type::Execve ||
      syscall_data.type == IAudispConsumer::SyscallRecordData::Type::ExecveAt) {

    if (!audit_event.execve_data.has_value()) {
      return Status::failure(
          "Missing an AUDIT_EXECVE record from an execve(at) event");
    }

    if (!audit_event.path_data.has_value()) {
      return Status::failure(
          "Missing an AUDIT_PATH record from an execve(at) event");
    }

    if (!audit_event.cwd_data.has_value()) {
      return Status::failure(
          "Missing an AUDIT_CWD record from an execve(at) event");
    }

    const auto &execve_data = audit_event.execve_data.value();
    row["argc"] = execve_data.argc;

    std::string command_line;
    for (const auto &parameter : execve_data.argument_list) {
      if (!command_line.empty()) {
        command_line.push_back(' ');
      }

      command_line += "\"" + parameter + "\"";
    }

    row["cmdline"] = command_line;

    const auto &path_record = audit_event.path_data.value();
    const auto &last_path_entry = path_record.front();

    row["path"] = last_path_entry.path;
    row["mode"] = last_path_entry.mode;
    row["owner_uid"] = last_path_entry.ouid;
    row["owner_gid"] = last_path_entry.ogid;

    const auto &cwd_data = audit_event.cwd_data.value();

    row["cwd"] = cwd_data;

  } else {
    row["owner_uid"] = {};
    row["owner_gid"] = {};
    row["argc"] = {};
    row["cmdline"] = {};
    row["path"] = {};
    row["mode"] = {};
    row["cwd"] = {};
  }

  return Status::success();
}
} // namespace zeek
