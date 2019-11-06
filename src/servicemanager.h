#pragma once

#include "izeekservicefactory.h"

#include <vector>

#include <zeek/ivirtualdatabase.h>

namespace zeek {
class ServiceManager final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using Ref = std::unique_ptr<ServiceManager>;

  static Status create(Ref &obj, IVirtualDatabase &virtual_database);
  ~ServiceManager();

  Status registerServiceFactory(IZeekServiceFactory::Ref service_factory);

  Status startServices();
  void stopServices();

  std::vector<std::string> serviceList() const;
  void checkServices();

protected:
  ServiceManager(IVirtualDatabase &virtual_database);

  Status spawnService(IZeekServiceFactory &factory);
};
} // namespace zeek
