#pragma once

#include "audispconsumer.h"
#include "iauparseinterface.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <zeek/iaudispconsumer.h>

namespace zeek {
class AudispConsumer final : public IAudispConsumer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~AudispConsumer() override;

protected:
  AudispConsumer(const std::string &audisp_socket_path);

  friend class IAudispConsumer;

public:
  struct SyscallRecordData final {
    enum class Type { Execve, ExecveAt, Fork, VFork, Clone };

    Type type;
    std::int64_t exit_code{0};
    std::int64_t process_id{0};
    std::int64_t parent_process_id{0};
    bool succeeded{false};
  };

  struct RawExecveRecordData final {
    int argc{0};
    std::map<std::string, std::string> argument_list;
  };

  struct ExecveRecordData final {
    int argc{0};
    std::vector<std::string> argument_list;
  };

  static Status parseSyscallRecord(std::optional<SyscallRecordData> &data,
                                   IAuparseInterface::Ref auparse);

  static Status parseRawExecveRecord(RawExecveRecordData &raw_data,
                                     IAuparseInterface::Ref auparse);

  static Status processExecveRecord(ExecveRecordData &data,
                                    RawExecveRecordData &raw_data);
};
} // namespace zeek
