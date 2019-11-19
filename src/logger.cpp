#include "logger.h"
#include "configuration.h"

namespace zeek {
namespace {
IZeekLogger::Ref zeek_logger;
} // namespace

Status initializeLogger(IVirtualDatabase &virtual_database) {
  IZeekLogger::Configuration logger_config;
  logger_config.log_folder = zeek::getConfig().getLogFolder();

  auto status =
      IZeekLogger::create(zeek_logger, logger_config, virtual_database);

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

void deinitializeLogger() { zeek_logger.reset(); }

IZeekLogger &getLogger() { return *zeek_logger.get(); }
} // namespace zeek
