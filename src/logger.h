#pragma once

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief Initializes a new logger object
/// \param virtual_database Where the logger table is registered
/// \return A Status object
Status initializeLogger(IVirtualDatabase &virtual_database);

/// \brief Deinitializes the logger object
void deinitializeLogger();

/// \return The logger object
IZeekLogger &getLogger();
} // namespace zeek
