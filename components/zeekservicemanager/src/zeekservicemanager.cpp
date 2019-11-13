#include "zeekservicemanager.h"
#include "zeekservicemanagertableplugin.h"

#include <future>
#include <unordered_map>

namespace zeek {
namespace {
struct ServiceInstance final {
  IZeekService::Ref service;
  std::future<Status> status;
};

Status serviceRunner(IZeekService &service, std::atomic_bool &terminate) {
  while (!terminate) {
    auto status = service.exec(terminate);
    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}
} // namespace

struct ZeekServiceManager::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekLogger &logger;

  std::atomic_bool terminate{false};

  std::unordered_map<std::string, IZeekServiceFactory::Ref>
      service_factory_list;

  std::unordered_map<std::string, ServiceInstance> service_list;
  std::string service_manager_table_name;
};

ZeekServiceManager::~ZeekServiceManager() {
  d->virtual_database.unregisterTable(d->service_manager_table_name);
}

Status ZeekServiceManager::registerServiceFactory(
    IZeekServiceFactory::Ref service_factory) {
  auto factory_name = service_factory->name();

  auto factory_it = d->service_factory_list.find(factory_name);
  if (factory_it != d->service_factory_list.end()) {
    return Status::failure(
        "The following service factory has already been registered: " +
        factory_name);
  }

  d->service_factory_list.insert({factory_name, std::move(service_factory)});

  return Status::success();
}

Status ZeekServiceManager::startServices() {
  for (const auto &p : d->service_factory_list) {
    const auto &factory_ref = p.second;
    auto &factory = *factory_ref.get();

    auto status = spawnService(factory);
    if (!status.succeeded()) {
      return status;
    }
  }

  return Status::success();
}

void ZeekServiceManager::stopServices() {
  d->terminate = true;

  for (auto &p : d->service_list) {
    const auto &service_name = p.first;
    auto &service_instance = p.second;

    auto status = service_instance.status.get();
    if (!status.succeeded()) {
      d->logger.logMessage(
          IZeekLogger::Severity::Error,
          "The service named '" + service_name +
              "' could not be stopped correctly: " + status.message());
    }
  }

  d->service_list.clear();
}

std::vector<std::string> ZeekServiceManager::serviceList() const {
  std::vector<std::string> output;

  for (auto &p : d->service_list) {
    const auto &service_name = p.first;
    output.push_back(service_name);
  }

  return output;
}

void ZeekServiceManager::checkServices() {
  for (auto service_it = d->service_list.begin();
       service_it != d->service_list.end();) {

    const auto &service_name = service_it->first;
    auto &service_instance = service_it->second;

    std::string status_description;
    if (service_instance.status.wait_for(std::chrono::seconds(0)) !=
        std::future_status::ready) {
      ++service_it;
      continue;
    }

    auto status = service_instance.status.get();

    d->logger.logMessage(
        IZeekLogger::Severity::Error,
        "The service named '" + service_name +
            "' has terminated with the following status: " + status.message());

    service_it = d->service_list.erase(service_it);
  }

  for (const auto &p : d->service_factory_list) {
    const auto &service_name = p.first;
    auto &factory = p.second;

    if (d->service_list.find(service_name) != d->service_list.end()) {
      continue;
    }

    auto status = spawnService(*factory.get());
    if (status.succeeded()) {
      d->logger.logMessage(IZeekLogger::Severity::Error,
                           "The service named '" + service_name +
                               "' has been successfully restarted");

    } else {
      d->logger.logMessage(IZeekLogger::Severity::Error,
                           "The service named '" + service_name +
                               "' could not be restarted");
    }
  }
}

ZeekServiceManager::ZeekServiceManager(IVirtualDatabase &virtual_database,
                                       IZeekLogger &logger)
    : d(new PrivateData(virtual_database, logger)) {

  ZeekServiceManagerTablePlugin::Ref service_manager_table;
  auto status =
      ZeekServiceManagerTablePlugin::create(service_manager_table, *this);
  if (!status.succeeded()) {
    throw status;
  }

  d->service_manager_table_name = service_manager_table->name();

  status = d->virtual_database.registerTable(service_manager_table);
  if (!status.succeeded()) {
    throw status;
  }
}

Status ZeekServiceManager::spawnService(IZeekServiceFactory &factory) {
  const auto &name = factory.name();

  auto service_it = d->service_list.find(name);
  if (service_it != d->service_list.end()) {
    return Status::failure("A service named '" + name + "' is already running");
  }

  {
    ServiceInstance service_instance = {};
    auto status = factory.spawn(service_instance.service);
    if (!status.succeeded()) {
      return Status::failure(
          "The '" + name +
          "' factory has failed to spawn the service: " + status.message());
    }

    d->service_list.insert({name, std::move(service_instance)});
  }

  auto &service_instance = d->service_list.at(name);
  auto &service_ref = *service_instance.service.get();

  service_instance.status =
      std::async(serviceRunner, std::ref(service_ref), std::ref(d->terminate));

  return Status::success();
}

Status IZeekServiceManager::create(Ref &obj, IVirtualDatabase &virtual_database,
                                   IZeekLogger &logger) {
  obj.reset();

  try {
    auto ptr = new ZeekServiceManager(virtual_database, logger);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
