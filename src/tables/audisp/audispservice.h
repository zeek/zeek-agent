#pragma once

#include <zeek/izeekservicemanager.h>

namespace zeek {
class AudispService final : public IZeekService {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~AudispService() override;

  virtual const std::string &name() const override;
  virtual Status exec(std::atomic_bool &terminate) override;

  AudispService(const AudispService &) = delete;
  AudispService &operator=(const AudispService &) = delete;

protected:
  AudispService(IVirtualDatabase &virtual_database);

  friend class AudispServiceFactory;
};

class AudispServiceFactory final : public IZeekServiceFactory {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(Ref &obj, IVirtualDatabase &virtual_database);
  virtual ~AudispServiceFactory() override;

  virtual const std::string &name() const override;
  virtual Status spawn(IZeekService::Ref &obj) override;

protected:
  AudispServiceFactory(IVirtualDatabase &virtual_database);
};
} // namespace zeek
