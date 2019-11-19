#pragma once

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeekconfiguration.h>

namespace zeek {
Status initializeConfiguration(IVirtualDatabase &virtual_database);
void deinitializeConfiguration();
IZeekConfiguration &getConfig();
} // namespace zeek
