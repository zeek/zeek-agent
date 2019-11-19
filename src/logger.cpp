#include "logger.h"

#include <iostream>

namespace zeek {
namespace {
IZeekLogger::Ref zeek_logger;
} // namespace

Status initializeLogger(const IZeekLogger::Configuration &configuration,
                        IVirtualDatabase &virtual_database) {

  auto status =
      IZeekLogger::create(zeek_logger, configuration, virtual_database);

  if (!status.succeeded()) {
    return status;
  }

  return Status::success();
}

void deinitializeLogger() { zeek_logger.reset(); }

IZeekLogger &getLogger() { return *zeek_logger.get(); }
} // namespace zeek
