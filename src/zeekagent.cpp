#include "zeekagent.h"
#include "logger.h"
#include "tables/audisp/audispservice.h"
#include "zeekconnection.h"

#include <chrono>
#include <iostream>
#include <thread>

namespace zeek {
struct ZeekAgent::PrivateData final {
  IVirtualDatabase::Ref virtual_database;
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
  IZeekServiceManager::Ref service_manager;
  auto status = initializeServiceManager(service_manager);
  if (!status.succeeded()) {
    return status;
  }

  status = service_manager->startServices();
  if (!status.succeeded()) {
    return status;
  }

  ZeekConnection::Ref zeek_connection;
  QueryScheduler::Ref query_scheduler;

  while (!terminate) {
    service_manager->checkServices();

    if (zeek_connection && query_scheduler) {
      auto status = zeek_connection->processEvents();

      if (!status.succeeded()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "The connection has been lost");

        zeek_connection.reset();

        query_scheduler->stop();
        query_scheduler.reset();

        continue;
      }

    } else {
      auto status = initializeConnection(zeek_connection);

      if (!status.succeeded()) {
        getLogger().logMessage(
            IZeekLogger::Severity::Error,
            "Reconnecting has failed. Retrying again later...");

        std::this_thread::sleep_for(std::chrono::seconds(5));
        continue;
      }

      status = initializeQueryScheduler(query_scheduler);
      if (!status.succeeded()) {
        auto status =
            Status::failure("Failed to initialize the query scheduler");

        getLogger().logMessage(IZeekLogger::Severity::Error, status.message());
        return status;
      }
    }

    auto task_queue = zeek_connection->getTaskQueue();
    query_scheduler->processTaskQueue(std::move(task_queue));

    auto task_output_list = query_scheduler->getTaskOutputList();
    if (!task_output_list.empty()) {
      auto status =
          zeek_connection->processTaskOutputList(std::move(task_output_list));
      if (!status.succeeded()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "Failed to process the task output list: " +
                                   status.message());
      }
    }
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Stopping all services");

  if (zeek_connection) {
    zeek_connection.reset();
  }

  if (query_scheduler) {
    query_scheduler->stop();
    query_scheduler.reset();
  }

  service_manager->stopServices();
  service_manager.reset();

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

Status ZeekAgent::initializeConnection(ZeekConnection::Ref &zeek_connection) {
  zeek_connection.reset();

  auto status = ZeekConnection::create(zeek_connection);
  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

Status
ZeekAgent::initializeQueryScheduler(QueryScheduler::Ref &query_scheduler) {
  if (query_scheduler) {
    query_scheduler->stop();
    query_scheduler.reset();
  }

  auto status =
      QueryScheduler::create(query_scheduler, *d->virtual_database.get());
  if (!status.succeeded()) {
    return status;
  }

  status = query_scheduler->start();
  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

Status
ZeekAgent::initializeServiceManager(IZeekServiceManager::Ref &service_manager) {
  auto &virtual_database = *d->virtual_database.get();

  auto status = IZeekServiceManager::create(service_manager, virtual_database,
                                            getLogger());

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

    status = service_manager->registerServiceFactory(
        std::move(audisp_service_factory));

    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}

void ZeekAgent::stopServices() {}
} // namespace zeek
