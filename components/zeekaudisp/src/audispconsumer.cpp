#include "audispconsumer.h"

#include <cstring>
#include <unordered_map>

#include <asm/unistd.h>

namespace zeek {
struct AudispConsumer::PrivateData final {
  std::string audisp_socket_path;
};

AudispConsumer::~AudispConsumer() {}

AudispConsumer::AudispConsumer(const std::string &audisp_socket_path)
    : d(new PrivateData) {
  d->audisp_socket_path = audisp_socket_path;
}

Status IAudispConsumer::create(Ref &obj,
                               const std::string &audisp_socket_path) {
  obj.reset();

  try {
    auto ptr = new AudispConsumer(audisp_socket_path);
    obj.reset(ptr);

    return Status::success();

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

Status AudispConsumer::processExecveRecord(ExecveRecordData &data,
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
} // namespace zeek
