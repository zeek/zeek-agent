#pragma once

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeekconfiguration.h>

namespace zeek {
/// \brief Initializes the configuration handler
/// \param virtual_database A virtual database instance used to install
///                         the configuration table
/// \return A Status object
Status initializeConfiguration(IVirtualDatabase &virtual_database);

/// \brief Deinitializes the configuration handler
void deinitializeConfiguration();

/// \return The configuration object
IZeekConfiguration &getConfig();
} // namespace zeek
