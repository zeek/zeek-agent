#pragma once

#include "audispconsumer.h"
#include "iauparseinterface.h"

#include <optional>

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
  };

  static Status parseSyscallRecord(std::optional<SyscallRecordData> &data,
                                   IAuparseInterface::Ref auparse);
};
} // namespace zeek
