#pragma once

#include <memory>

#include <auparse.h>

#include <zeek/status.h>

namespace zeek {
class IAudispProducer {
public:
  using Ref = std::shared_ptr<IAudispProducer>;

  IAudispProducer() = default;
  virtual ~IAudispProducer() = default;

  virtual Status read(std::string &buffer) = 0;

  IAudispProducer(const IAudispProducer &other) = delete;
  IAudispProducer &operator=(const IAudispProducer &other) = delete;
};
} // namespace zeek
