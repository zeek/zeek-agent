#include "zeekservicemanagertableplugin.h"

namespace zeek {
struct ZeekServiceManagerTablePlugin::PrivateData final {
  PrivateData(IZeekServiceManager &service_manager_)
      : service_manager(service_manager_) {}

  IZeekServiceManager &service_manager;
};

Status
ZeekServiceManagerTablePlugin::create(Ref &obj,
                                      IZeekServiceManager &service_manager) {

  obj.reset();

  try {
    auto ptr = new ZeekServiceManagerTablePlugin(service_manager);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekServiceManagerTablePlugin::~ZeekServiceManagerTablePlugin() {}

const std::string &ZeekServiceManagerTablePlugin::name() const {
  static const std::string kTableName{"zeek_service_manager"};
  return kTableName;
}

const ZeekServiceManagerTablePlugin::Schema &
ZeekServiceManagerTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "name", IVirtualTable::ColumnType::String }
  };
  // clang-format on

  return kTableSchema;
}

Status ZeekServiceManagerTablePlugin::generateRowList(RowList &row_list) {
  row_list = {};

  for (const auto &service_name : d->service_manager.serviceList()) {
    Row row = {};

    row.insert({"name", service_name});
    row_list.push_back(std::move(row));
  }

  return Status::success();
}

ZeekServiceManagerTablePlugin::ZeekServiceManagerTablePlugin(
    IZeekServiceManager &service_manager)
    : d(new PrivateData(service_manager)) {}
} // namespace zeek
