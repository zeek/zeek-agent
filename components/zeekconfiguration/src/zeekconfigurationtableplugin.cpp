#include "zeekconfigurationtableplugin.h"

#include <chrono>
#include <mutex>

namespace zeek {
struct ZeekConfigurationTablePlugin::PrivateData final {
  PrivateData(IZeekConfiguration &configuration_)
      : configuration(configuration_) {}

  IZeekConfiguration &configuration;
};

Status ZeekConfigurationTablePlugin::create(Ref &obj,
                                            IZeekConfiguration &configuration) {
  obj.reset();

  try {
    auto ptr = new ZeekConfigurationTablePlugin(configuration);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekConfigurationTablePlugin::~ZeekConfigurationTablePlugin() {}

const std::string &ZeekConfigurationTablePlugin::name() const {
  static const std::string kTableName{"zeek_configuration"};

  return kTableName;
}

const ZeekConfigurationTablePlugin::Schema &
ZeekConfigurationTablePlugin::schema() const {
  // clang-format off
  static const Schema kTableSchema = {
    { "key", IVirtualTable::ColumnType::String },
    { "value", IVirtualTable::ColumnType::String }
  };
  // clang-format on

  return kTableSchema;
}

Status ZeekConfigurationTablePlugin::generateRowList(RowList &row_list) {
  row_list = {};

  return Status::success();
}

ZeekConfigurationTablePlugin::ZeekConfigurationTablePlugin(
    IZeekConfiguration &configuration)
    : d(new PrivateData(configuration)) {}

Status ZeekConfigurationTablePlugin::generateRow(Row &row) {
  row = {};
  return Status::success();
}
} // namespace zeek
