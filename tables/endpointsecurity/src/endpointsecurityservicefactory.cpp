#include "endpointsecurityservice.h"

namespace zeek {
Status registerEndpointSecurityServiceFactory(
    IZeekServiceManager &service_manager, IVirtualDatabase &virtual_database,
    IZeekConfiguration &configuration, IZeekLogger &logger) {

  EndpointSecurityServiceFactory::Ref endpoint_sec_service_factory;
  auto status = EndpointSecurityServiceFactory::create(
      endpoint_sec_service_factory, virtual_database, configuration, logger);

  if (!status.succeeded()) {
    return status;
  }

  status = service_manager.registerServiceFactory(
      std::move(endpoint_sec_service_factory));

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}
} // namespace zeek
