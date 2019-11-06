#include "tables/service_manager/servicemanagertableplugin.h"

namespace zeek {
struct ServiceManagerTablePlugin::PrivateData final {
  PrivateData(ServiceManager &service_manager_)
      : service_manager(service_manager_) {}

  ServiceManager &service_manager;
};

Status ServiceManagerTablePlugin::create(Ref &obj,
                                         ServiceManager &service_manager) {
  obj.reset();

  try {
    auto ptr = new ServiceManagerTablePlugin(service_manager);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ServiceManagerTablePlugin::~ServiceManagerTablePlugin() {}

const std::string &ServiceManagerTablePlugin::name() const {
  static const std::string kTableName{"zeek_service_manager"};
  return kTableName;
}

const ServiceManagerTablePlugin::Schema &
ServiceManagerTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "name", IVirtualTable::ColumnType::String }
  };
  // clang-format on

  return kTableSchema;
}

Status ServiceManagerTablePlugin::generateRowList(RowList &row_list) {
  row_list = {};

  for (const auto &service_name : d->service_manager.serviceList()) {
    Row row = {};

    row.insert({"name", service_name});
    row_list.push_back(std::move(row));
  }

  return Status::success();
}

ServiceManagerTablePlugin::ServiceManagerTablePlugin(
    ServiceManager &service_manager)
    : d(new PrivateData(service_manager)) {}
} // namespace zeek
