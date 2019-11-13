#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

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

class IZeekServiceManager {
public:
  using Ref = std::unique_ptr<IZeekServiceManager>;

  static Status create(Ref &obj, IVirtualDatabase &virtual_database,
                       IZeekLogger &logger);

  IZeekServiceManager() = default;
  virtual ~IZeekServiceManager() = default;

  virtual Status
  registerServiceFactory(IZeekServiceFactory::Ref service_factory) = 0;

  virtual Status startServices() = 0;
  virtual void stopServices() = 0;

  virtual std::vector<std::string> serviceList() const = 0;
  virtual void checkServices() = 0;
};
} // namespace zeek
