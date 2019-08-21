#include "audispconsumer.h"

#include <cstring>
#include <iostream>
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

    if (field_count == 4U) {
      break;
    }

  } while (auparse->nextField() > 0);

  if (field_count != 4U) {
    return Status::failure("One or more fields are missing");
  }

  data = std::move(output);
  return Status::success();
}
} // namespace zeek
