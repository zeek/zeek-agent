#pragma once

#include <memory>

#include <zeek/status.h>

namespace zeek {
class IAudispConsumer {
public:
  using Ref = std::shared_ptr<IAudispConsumer>;
  static Status create(Ref &obj, const std::string &audisp_socket_path);

  IAudispConsumer() = default;
  virtual ~IAudispConsumer() = default;

  IAudispConsumer(const IAudispConsumer &other) = delete;
  IAudispConsumer &operator=(const IAudispConsumer &other) = delete;
};
} // namespace zeek
