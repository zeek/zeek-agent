#include "configuration.h"

namespace zeek {
namespace {
const std::string kConfigurationFilePath{"/etc/zeek-agent/config.json"};

IZeekConfiguration::Ref zeek_config;
} // namespace

Status initializeConfiguration(IVirtualDatabase &virtual_database) {
  auto status = IZeekConfiguration::create(zeek_config, virtual_database,
                                           kConfigurationFilePath);

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

void deinitializeConfiguration() { zeek_config.reset(); }

IZeekConfiguration &getConfig() { return *zeek_config.get(); }
} // namespace zeek
