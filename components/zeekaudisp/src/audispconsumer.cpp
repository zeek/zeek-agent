#include "audispconsumer.h"
#include "audispsocketreader.h"
#include "auparseinterface.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <unordered_map>

#include <asm/unistd.h>
#include <libaudit.h>

namespace zeek {
struct AudispConsumer::PrivateData final {
  IAudispProducer::Ref audisp_producer;
  IAuparseInterface::Ref auparse_interface;

  std::mutex processed_event_list_mutex;
  AuditEventList processed_event_list;

  std::atomic_bool parser_error{false};
};

Status
AudispConsumer::createWithProducer(Ref &obj,
                                   IAudispProducer::Ref audisp_producer) {
  obj.reset();

  try {
    auto ptr = new AudispConsumer(std::move(audisp_producer));
    audisp_producer = {};

    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

AudispConsumer::~AudispConsumer() { d->auparse_interface->flushFeed(); }

Status AudispConsumer::processEvents() {
  std::string buffer;
  auto status = d->audisp_producer->read(buffer);
  if (!status.succeeded()) {
    return status;
  }

  d->auparse_interface->feed(buffer.data(), buffer.size());
  return Status::success();
}

Status AudispConsumer::getEvents(AuditEventList &event_list) {
  event_list = {};

  d->auparse_interface->flushFeed();

  {
    std::lock_guard<std::mutex> lock(d->processed_event_list_mutex);

    event_list = std::move(d->processed_event_list);
    d->processed_event_list = {};
  }

  Status status;
  if (d->parser_error) {
    status =
        Status::failure("One or more events could not be parsed correctly");
    d->parser_error = false;
  } else {
    status = Status::success();
  }

  return status;
}

AudispConsumer::AudispConsumer(IAudispProducer::Ref audisp_producer)
    : d(new PrivateData) {
  d->audisp_producer = std::move(audisp_producer);
  audisp_producer = {};

  auto status = AuparseInterface::create(d->auparse_interface);
  if (!status.succeeded()) {
    throw status;
  }

  d->auparse_interface->addCallback(auparseCallbackDispatcher, this, nullptr);
}

void AudispConsumer::auparseCallbackDispatcher(auparse_state_t *,
                                               auparse_cb_event_t event_type,
                                               void *user_data) {

  auto &instance = *static_cast<AudispConsumer *>(user_data);
  instance.auparseCallback(event_type);
}

void AudispConsumer::auparseCallback(auparse_cb_event_t event_type) {
  if (event_type != AUPARSE_CB_EVENT_READY) {
    return;
  }

  d->auparse_interface->firstRecord();

  auto record_type = d->auparse_interface->getType();
  if (record_type != AUDIT_SYSCALL) {
    return;
  }

  AuditEvent audit_event;
  std::optional<SyscallRecordData> syscall_data;
  auto status = parseSyscallRecord(syscall_data, d->auparse_interface);
  if (!status.succeeded()) {
    d->parser_error = true;
    return;
  }

  if (!syscall_data.has_value()) {
    return;
  }

  audit_event.syscall_data = std::move(syscall_data.value());
  syscall_data = {};

  IAudispConsumer::RawExecveRecordData raw_execve_data;
  IAudispConsumer::PathRecordData path_data;
  std::string cwd_data;

  while (d->auparse_interface->nextRecord() > 0) {
    record_type = d->auparse_interface->getType();
    Status status;

    switch (record_type) {
    case AUDIT_EXECVE:
      status = parseRawExecveRecord(raw_execve_data, d->auparse_interface);
      break;

    case AUDIT_CWD:
      status = parseCwdRecord(cwd_data, d->auparse_interface);
      break;

    case AUDIT_PATH:
      status = parsePathRecord(path_data, d->auparse_interface);
      break;

    default:
      status = Status::success();
      break;
    }

    if (!status.succeeded()) {
      d->parser_error = true;
      return;
    }
  }

  bool process_execve_records{false};

  switch (audit_event.syscall_data.type) {
  case IAudispConsumer::SyscallRecordData::Type::Execve:
  case IAudispConsumer::SyscallRecordData::Type::ExecveAt:
    process_execve_records = true;
    break;

  case IAudispConsumer::SyscallRecordData::Type::Fork:
  case IAudispConsumer::SyscallRecordData::Type::VFork:
  case IAudispConsumer::SyscallRecordData::Type::Clone:
    process_execve_records = false;
    break;

  default:
    d->parser_error = true;
    return;
  }

  if (process_execve_records) {
    if (raw_execve_data.argument_list.empty()) {
      d->parser_error = true;
      return;
    }

    IAudispConsumer::ExecveRecordData execve_data;
    status = processExecveRecords(execve_data, raw_execve_data);
    if (!status.succeeded()) {
      d->parser_error = true;
      return;
    }

    if (execve_data.argument_list.empty()) {
      d->parser_error = true;
      return;
    }

    audit_event.execve_data = std::move(execve_data);
    execve_data = {};

    if (path_data.empty()) {
      d->parser_error = true;
      return;
    }

    audit_event.path_data = std::move(path_data);
    path_data = {};

    audit_event.cwd_data = std::move(cwd_data);
    cwd_data = {};
  }

  {
    std::lock_guard<std::mutex> lock(d->processed_event_list_mutex);
    d->processed_event_list.push_back(std::move(audit_event));
  }
}

Status IAudispConsumer::create(Ref &obj,
                               const std::string &audisp_socket_path) {
  obj.reset();

  try {
    IAudispProducer::Ref audisp_producer;
    auto status =
        AudispSocketReader::create(audisp_producer, audisp_socket_path);
    if (!status.succeeded()) {
      return status;
    }

    return AudispConsumer::createWithProducer(obj, std::move(audisp_producer));

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

Status
AudispConsumer::parseSyscallRecord(std::optional<SyscallRecordData> &data,
                                   IAuparseInterface::Ref auparse) {
  // clang-format off
  std::unordered_map<int, SyscallRecordData::Type> kNumberToSyscallType = {
    { __NR_execve, SyscallRecordData::Type::Execve },
    { __NR_execveat, SyscallRecordData::Type::ExecveAt },
    { __NR_fork, SyscallRecordData::Type::Fork },
    { __NR_vfork, SyscallRecordData::Type::VFork },
    { __NR_clone, SyscallRecordData::Type::Clone },
  };
  // clang-format on

  data.reset();

  SyscallRecordData output;

  std::int64_t syscall_number{0};
  std::size_t field_count{0U};

  auparse->firstField();

  do {
    auto field_name = auparse->getFieldName();
    auto field_value = auparse->getFieldStr();

    if (std::strcmp(field_name, "syscall") == 0) {
      syscall_number = std::strtoll(field_value, nullptr, 10);

      auto syscall_type_it = kNumberToSyscallType.find(syscall_number);
      if (syscall_type_it == kNumberToSyscallType.end()) {
        return Status::success();
      }

      output.type = syscall_type_it->second;

      ++field_count;

    } else if (std::strcmp(field_name, "success") == 0) {
      output.succeeded = std::strcmp(field_value, "yes") == 0;
      ++field_count;

    } else if (std::strcmp(field_name, "exit") == 0) {
      output.exit_code = std::strtoll(field_value, nullptr, 10);
      ++field_count;

    } else if (std::strcmp(field_name, "pid") == 0) {
      output.process_id = std::strtoll(field_value, nullptr, 10);
      ++field_count;

    } else if (std::strcmp(field_name, "ppid") == 0) {
      output.parent_process_id = std::strtoll(field_value, nullptr, 10);
      ++field_count;
    }

    if (field_count == 5U) {
      break;
    }

  } while (auparse->nextField() > 0);

  if (field_count != 5U) {
    return Status::failure("One or more fields are missing");
  }

  data = std::move(output);
  return Status::success();
}

Status AudispConsumer::parseRawExecveRecord(RawExecveRecordData &raw_data,
                                            IAuparseInterface::Ref auparse) {
  auparse->firstField();

  do {
    auto field_name = auparse->getFieldName();
    auto field_value = auparse->getFieldStr();

    if (std::strcmp(field_name, "argc") == 0) {
      raw_data.argc = std::strtol(field_value, nullptr, 10);
      if (raw_data.argc == 0) {
        break;
      }

      continue;

    } else if (field_name[0] != 'a' ||
               std::strstr(field_name, "_len") != nullptr) {

      continue;
    }

    raw_data.argument_list.insert({field_name, field_value});
  } while (auparse->nextField() > 0);

  return Status::success();
}

Status AudispConsumer::processExecveRecords(ExecveRecordData &data,
                                            RawExecveRecordData &raw_data) {
  data = {};

  ExecveRecordData output;
  output.argc = raw_data.argc;

  for (auto &p : raw_data.argument_list) {
    auto &field_name = p.first;
    auto &field_value = p.second;

    if (field_name.find("_len") != std::string::npos) {
      continue;
    }

    auto separator_index = field_name.find("[");
    if (separator_index == std::string::npos) {
      continue;

    } else {
      auto base_field_name = field_name.substr(0, separator_index);
      auto chunk_index =
          std::strtol(field_name.data() + separator_index, nullptr, 10U);
      auto base_field_it = raw_data.argument_list.find(base_field_name);

      if (chunk_index != 0 && base_field_it == raw_data.argument_list.end()) {
        return Status::failure("Missing execve argument");
      }

      if (base_field_it == raw_data.argument_list.end()) {
        raw_data.argument_list.insert({base_field_name, field_value});
      } else {
        auto &base_field_value = base_field_it->second;
        base_field_value.append(field_value);
      }
    }
  }

  for (auto &p : raw_data.argument_list) {
    const auto &field_name = p.first;
    auto &field_value = p.second;

    if (field_name.find('[') != std::string::npos) {
      continue;
    }

    if (field_name.find("_len") != std::string::npos) {
      continue;
    }

    output.argument_list.push_back(std::move(field_value));
  }

  raw_data = {};
  data = std::move(output);

  return Status::success();
}

Status AudispConsumer::parseCwdRecord(std::string &data,
                                      IAuparseInterface::Ref auparse) {
  data = {};

  auparse->firstField();

  do {
    auto field_name = auparse->getFieldName();
    auto field_value = auparse->getFieldStr();

    if (std::strcmp(field_name, "cwd") == 0) {
      data = field_value;
      break;
    }
  } while (auparse->nextField() > 0);

  if (data.empty()) {
    return Status::failure(
        "The cwd field was missing from the AUDIT_CWD record");
  }

  return Status::success();
}

Status AudispConsumer::parsePathRecord(PathRecordData &data,
                                       IAuparseInterface::Ref auparse) {
  auparse->firstField();

  std::string path_value;
  bool first_record{false};

  std::size_t parsed_field_count{0U};

  do {
    auto field_name = auparse->getFieldName();
    auto field_value = auparse->getFieldStr();

    if (std::strcmp(field_name, "name") == 0) {
      path_value = field_value;
      ++parsed_field_count;

    } else if (std::strcmp(field_name, "item") == 0) {
      if (std::strcmp(field_value, "0") == 0) {
        first_record = true;
      }

      ++parsed_field_count;
    }

    if (parsed_field_count == 2U) {
      break;
    }

  } while (auparse->nextField() > 0);

  if (parsed_field_count != 2U) {
    return Status::failure(
        "One or more fields are missing from the AUDIT_PATH record");
  }

  if (first_record) {
    data = {};
  }

  data.push_back(std::move(path_value));
  return Status::success();
}
} // namespace zeek
