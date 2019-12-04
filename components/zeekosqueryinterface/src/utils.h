#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
Status getOsqueryTableList(std::vector<std::string> &table_list);
Status getOsqueryTableSchema(IVirtualTable::Schema &table_schema,
                             const std::string &table_name);
} // namespace zeek
