#include "zeekconfigurationtableplugin.h"

#include <chrono>
#include <mutex>
#include <string>
#include <vector>

namespace zeek {
namespace {
void generateRow(IVirtualTable::RowList &row_list, const std::string &key_name,
                 const std::string &value) {

  IVirtualTable::Row row;
  row["key"] = key_name;
  row["value"] = value;

  row_list.push_back(std::move(row));
}

void generateRow(IVirtualTable::RowList &row_list, const std::string &key_name,
                 const std::int64_t &value) {

  generateRow(row_list, key_name, std::to_string(value));
}

void generateRow(IVirtualTable::RowList &row_list, const std::string &key_name,
                 const std::vector<std::string> &value) {

  std::string converted_value;
  for (const auto &s : value) {
    if (!converted_value.empty()) {
      converted_value += ", ";
    }

    converted_value += s;
  }

  IVirtualTable::Row row;
  row["key"] = key_name;
  row["value"] = converted_value;

  row_list.push_back(std::move(row));
}
} // namespace

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

  generateRow(row_list, "server_address", d->configuration.serverAddress());
  generateRow(row_list, "server_port", d->configuration.serverPort());
  generateRow(row_list, "group_list", d->configuration.groupList());
  generateRow(row_list, "log_folder", d->configuration.getLogFolder());

  generateRow(row_list, "certificate_authority",
              d->configuration.certificateAuthority());

  generateRow(row_list, "client_certificate",
              d->configuration.clientCertificate());

  generateRow(row_list, "client_key", d->configuration.clientKey());

  generateRow(row_list, "osquery_extensions_socket",
              d->configuration.osqueryExtensionsSocket());

  generateRow(row_list, "max_queued_row_count",
              d->configuration.maxQueuedRowCount());

  return Status::success();
}

ZeekConfigurationTablePlugin::ZeekConfigurationTablePlugin(
    IZeekConfiguration &configuration)
    : d(new PrivateData(configuration)) {}
} // namespace zeek
