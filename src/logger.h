#pragma once

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

namespace zeek {
Status initializeLogger(IVirtualDatabase &virtual_database);
void deinitializeLogger();
IZeekLogger &getLogger();
} // namespace zeek
