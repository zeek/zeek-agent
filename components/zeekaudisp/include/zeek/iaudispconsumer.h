#pragma once

#include <map>
#include <memory>
#include <vector>

#include <zeek/status.h>

namespace zeek {
class IAudispConsumer {
public:
  struct SyscallRecordData final {
    enum class Type { Execve, ExecveAt, Fork, VFork, Clone, Bind, Connect };

    Type type;
    std::int64_t exit_code{0};
    std::int64_t process_id{0};
    std::int64_t parent_process_id{0};
    bool succeeded{false};
    std::int64_t auid{0};
    std::int64_t uid{0};
    std::int64_t euid{0};
    std::int64_t gid{0};
    std::int64_t egid{0};
    std::string exe;
    std::string a0;
  };

  struct RawExecveRecordData final {
    int argc{0};
    std::map<std::string, std::string> argument_list;
  };

  struct ExecveRecordData final {
    int argc{0};
    std::vector<std::string> argument_list;
  };

  struct PathRecord final {
    std::string path;
    std::int64_t mode{0};
    std::int64_t ouid{0};
    std::int64_t ogid{0};
  };

  using PathRecordData = std::vector<PathRecord>;

  struct SockaddrRecordData final {
    std::string family;
    std::int64_t port{0};
    std::string address;
  };

  struct AuditEvent final {
    SyscallRecordData syscall_data;
    std::optional<ExecveRecordData> execve_data;
    std::optional<PathRecordData> path_data;
    std::optional<std::string> cwd_data;
    std::optional<SockaddrRecordData> sockaddr_data;
  };

  using AuditEventList = std::vector<AuditEvent>;

  using Ref = std::unique_ptr<IAudispConsumer>;
  static Status create(Ref &obj, const std::string &audisp_socket_path);

  IAudispConsumer() = default;
  virtual ~IAudispConsumer() = default;

  virtual Status processEvents() = 0;
  virtual Status getEvents(AuditEventList &event_list) = 0;

  IAudispConsumer(const IAudispConsumer &other) = delete;
  IAudispConsumer &operator=(const IAudispConsumer &other) = delete;
};
} // namespace zeek
