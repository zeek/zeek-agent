#pragma once

#include <zeek/izeekservicemanager.h>

namespace zeek {
class ZeekServiceManager final : public IZeekServiceManager {
public:
  virtual ~ZeekServiceManager() override;

  virtual Status
  registerServiceFactory(IZeekServiceFactory::Ref service_factory) override;

  virtual Status startServices() override;
  virtual void stopServices() override;

  virtual std::vector<std::string> serviceList() const override;
  virtual void checkServices() override;

protected:
  ZeekServiceManager(IVirtualDatabase &virtual_database, IZeekLogger &logger);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Status spawnService(IZeekServiceFactory &factory);

  friend class IZeekServiceManager;
};
} // namespace zeek
