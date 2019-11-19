#include "zeekagent.h"
#include "logger.h"
#include "tables/audisp/audispservice.h"

#include <chrono>
#include <iostream>
#include <thread>

#include <zeek/izeekservicemanager.h>

namespace zeek {
struct ZeekAgent::PrivateData final {
  IVirtualDatabase::Ref virtual_database;
  IZeekServiceManager::Ref service_manager;
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
  auto status = initializeServiceManager();
  if (!status.succeeded()) {
    throw status;
  }

  status = d->service_manager->startServices();
  if (!status.succeeded()) {
    return status;
  }

  // TODO(alessandro): Add zeek connection handling here

  // Test code
  static const std::vector<std::string> kQueryList = {
      "SELECT * FROM socket_events", "SELECT * FROM process_events",
      "SELECT * FROM zeek_service_manager", "SELECT * FROM zeek_logger"};

  while (!terminate) {
    d->service_manager->checkServices();

    for (const auto &query : kQueryList) {
      IVirtualTable::RowList row_list;
      status = d->virtual_database->query(row_list, query);

      if (!status.succeeded()) {
        getLogger().logMessage(IZeekLogger::Severity::Error,
                               "Failed to query the database: " +
                                   status.message());
        continue;
      }

      if (row_list.empty()) {
        continue;
      }

      std::cout << "\n\n\nResults for query " << query << "\n";
      for (const auto &current_row : row_list) {
        for (const auto &p : current_row) {
          const auto &column_name = p.first;
          const auto &column_value = p.second;

          if (!column_value.has_value()) {
            continue;
          }

          std::cout << column_name << ": '";
          const auto &column_value_data = column_value.value();

          switch (column_value_data.index()) {
          case 0U:
            std::cout << std::get<0>(column_value_data);
            break;

          case 1U:
            std::cout << std::get<1>(column_value_data);
            break;

          default:
            std::cout << "<INVALID TYPE>";
            break;
          }

          std::cout << "' ";
        }

        std::cout << "\n";
      }

      std::this_thread::sleep_for(std::chrono::seconds(2));
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
