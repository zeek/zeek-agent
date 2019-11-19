#include "zeekagent.h"
#include "logger.h"
#include "tables/audisp/audispservice.h"
#include "zeekconnection.h"

#include <chrono>
#include <iostream>
#include <thread>

#include <zeek/izeekservicemanager.h>

namespace zeek {
struct ZeekAgent::PrivateData final {
  IVirtualDatabase::Ref virtual_database;
  IZeekServiceManager::Ref service_manager;
  ZeekConnection::Ref zeek_connection;
};

Status ZeekAgent::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new ZeekAgent();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekAgent::~ZeekAgent() {}

Status ZeekAgent::exec(std::atomic_bool &terminate) {
  auto status = initializeConnection();
  if (!status.succeeded()) {
    return status;
  }

  status = initializeServiceManager();
  if (!status.succeeded()) {
    return status;
  }

  status = d->service_manager->startServices();
  if (!status.succeeded()) {
    return status;
  }

  while (!terminate) {
    d->service_manager->checkServices();

    if (d->zeek_connection) {
      status = d->zeek_connection->processEvents();
    } else {
      status = initializeConnection();
    }

    if (!status.succeeded()) {
      getLogger().logMessage(
          IZeekLogger::Severity::Error,
          "The connection has been lost. Attempting to reconnect...");

      status = initializeConnection();
      if (!status.succeeded()) {
        getLogger().logMessage(
            IZeekLogger::Severity::Error,
            "Reconnecting has failed. Retrying again later...");

        std::this_thread::sleep_for(std::chrono::seconds(2));
        continue;
      }
    }
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Stopping all services");

  d->service_manager->stopServices();
  d->service_manager.reset();

  getLogger().logMessage(IZeekLogger::Severity::Information, "Terminating");

  return Status::success();
}

IVirtualDatabase &ZeekAgent::virtualDatabase() {
  return *d->virtual_database.get();
}

ZeekAgent::ZeekAgent() : d(new PrivateData) {
  auto status = IVirtualDatabase::create(d->virtual_database);
  if (!status.succeeded()) {
    throw status;
  }
}

Status ZeekAgent::initializeConnection() {
  d->zeek_connection.reset();

  auto status = ZeekConnection::create(d->zeek_connection);
  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

Status ZeekAgent::initializeServiceManager() {
  auto &virtual_database = *d->virtual_database.get();

  auto status = IZeekServiceManager::create(d->service_manager,
                                            virtual_database, getLogger());
  if (!status.succeeded()) {
    throw status;
  }

  {
    AudispServiceFactory::Ref audisp_service_factory;
    status =
        AudispServiceFactory::create(audisp_service_factory, virtual_database);

    if (!status.succeeded()) {
      return status;
    }

    status = d->service_manager->registerServiceFactory(
        std::move(audisp_service_factory));

    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}

void ZeekAgent::stopServices() {}
} // namespace zeek
