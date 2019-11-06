#pragma once

#include <atomic>
#include <memory>

#include <zeek/status.h>

namespace zeek {
class IZeekService {
public:
  using Ref = std::unique_ptr<IZeekService>;

  IZeekService() = default;
  virtual ~IZeekService() = default;

  virtual const std::string &name() const = 0;
  virtual Status exec(std::atomic_bool &terminate) = 0;
};

class IZeekServiceFactory {
public:
  using Ref = std::unique_ptr<IZeekServiceFactory>;

  IZeekServiceFactory() = default;
  virtual ~IZeekServiceFactory() = default;

  virtual const std::string &name() const = 0;
  virtual Status spawn(IZeekService::Ref &obj) = 0;
};
} // namespace zeek
