#pragma once

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

namespace zeek {
Status initializeLogger(const IZeekLogger::Configuration &configuration,
                        IVirtualDatabase &virtual_database);

void deinitializeLogger();

IZeekLogger &getLogger();

void logMessage(IZeekLogger::Severity severity, const std::string &message);
} // namespace zeek
