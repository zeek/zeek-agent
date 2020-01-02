#pragma once

#include <zeek/izeekservicemanager.h>

namespace zeek {
/// \brief The Zeek Agent service manager (implementation)
class ZeekServiceManager final : public IZeekServiceManager {
public:
  /// \brief Constructor
  virtual ~ZeekServiceManager() override;

  /// \brief Registers a new service factory
  /// \param service_factory A reference to a service factory object
  /// \return A Status object
  virtual Status
  registerServiceFactory(IZeekServiceFactory::Ref service_factory) override;

  /// \brief Starts all registered services
  /// \return A Status object
  virtual Status startServices() override;

  /// \brief Stops all services
  virtual void stopServices() override;

  /// \return The list of registered services
  virtual std::vector<std::string> serviceList() const override;

  /// \brief Tests the status of all services and restarts them if needed
  virtual void checkServices() override;

protected:
  /// \brief Constructor
  /// \param virtual_database A reference to virtual database
  /// \param logger A reference to a logger object
  ZeekServiceManager(IVirtualDatabase &virtual_database, IZeekLogger &logger);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Creates a new service with the given factory
  /// \param factory The service factory object
  /// \return A Status object
  Status spawnService(IZeekServiceFactory &factory);

  friend class IZeekServiceManager;
};
} // namespace zeek
