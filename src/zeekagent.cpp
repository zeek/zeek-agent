#include "zeekagent.h"
#include "servicemanager.h"
#include "tables/audisp/audispservice.h"

#include <chrono>
#include <iostream>
#include <thread>

#include <zeek/ivirtualdatabase.h>

namespace zeek {
struct ZeekAgent::PrivateData final {
  IVirtualDatabase::Ref virtual_database;
  ServiceManager::Ref service_manager;
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
  auto status = d->service_manager->startServices();
  if (!status.succeeded()) {
    return status;
  }

  while (!terminate) {
    // TODO(alessandro): Add zeek connection handling here
    std::this_thread::sleep_for(std::chrono::seconds(1));

    d->service_manager->checkServices();

    // Test code
    IVirtualTable::RowList row_list;
    status =
        d->virtual_database->query(row_list, "SELECT * FROM process_events");

    if (!status.succeeded()) {
      std::cerr << "Failed to query the database: " << status.message() << "\n";
      continue;
    }

    if (row_list.empty()) {
      continue;
    }

    std::cout << "Query result:\n";
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
  }

  d->service_manager->stopServices();
  return Status::success();
}

ZeekAgent::ZeekAgent() : d(new PrivateData) {
  auto status = IVirtualDatabase::create(d->virtual_database);
  if (!status.succeeded()) {
    throw status;
  }

  status = initializeServiceManager();
  if (!status.succeeded()) {
    throw status;
  }
}

Status ZeekAgent::initializeServiceManager() {
  auto &virtual_database = *d->virtual_database.get();

  auto status = ServiceManager::create(d->service_manager, virtual_database);
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
