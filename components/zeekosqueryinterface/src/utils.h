#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
/// \brief Enumerates all active osquery tables
/// \param table_list Where the list is stored
/// \return A Status object
Status getOsqueryTableList(std::vector<std::string> &table_list);

/// \brief Returns the schema for the specified osquery table
/// \param table_schema Where the table schema is stored
/// \param table_name The name of the osquery table
/// \return A Status object
Status getOsqueryTableSchema(IVirtualTable::Schema &table_schema,
                             const std::string &table_name);
} // namespace zeek
