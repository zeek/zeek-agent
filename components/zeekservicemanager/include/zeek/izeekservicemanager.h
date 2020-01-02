#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief An interface for Zeek Agent services
class IZeekService {
public:
  /// \brief A reference to a running service
  using Ref = std::unique_ptr<IZeekService>;

  /// \brief Constructor
  IZeekService() = default;

  /// \brief Destructor
  virtual ~IZeekService() = default;

  /// \brief Service name
  virtual const std::string &name() const = 0;

  /// \brief Main loop for the service
  /// \param terminate When set to true, the service should terminate
  /// \return A Status object
  virtual Status exec(std::atomic_bool &terminate) = 0;
};

/// \brief An interface for service factories
class IZeekServiceFactory {
public:
  /// \brief A reference to a service factory
  using Ref = std::unique_ptr<IZeekServiceFactory>;

  /// \brief Constructor
  IZeekServiceFactory() = default;

  /// \brief Destructor
  virtual ~IZeekServiceFactory() = default;

  /// \brief Returns the factory name
  virtual const std::string &name() const = 0;

  /// \brief Spawns a new service
  /// \param obj Where the newly created service is stored
  virtual Status spawn(IZeekService::Ref &obj) = 0;
};

/// \brief The Zeek Agent service manager (implementation)
class IZeekServiceManager {
public:
  /// \brief A reference to a service manager
  using Ref = std::unique_ptr<IZeekServiceManager>;

  /// \brief Factory method
  /// \param obj Where the service manager is stored
  /// \param virtual_database A reference to a valid virtual database
  /// \param logger A reference to a valid logger object
  /// \return A Status object
  static Status create(Ref &obj, IVirtualDatabase &virtual_database,
                       IZeekLogger &logger);

  /// \brief Constructor
  IZeekServiceManager() = default;

  /// \brief Destructor
  virtual ~IZeekServiceManager() = default;

  /// \brief Registers a new service factory
  /// \param service_factory A reference to a service factory object
  /// \return A Status object
  virtual Status
  registerServiceFactory(IZeekServiceFactory::Ref service_factory) = 0;

  /// \brief Starts all registered services
  /// \return A Status object
  virtual Status startServices() = 0;

  /// \brief Stops all services
  virtual void stopServices() = 0;

  /// \return The list of registered services
  virtual std::vector<std::string> serviceList() const = 0;

  /// \brief Tests the status of all services and restarts them if needed
  virtual void checkServices() = 0;
};
} // namespace zeek
