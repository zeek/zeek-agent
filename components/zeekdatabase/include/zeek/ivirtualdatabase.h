#pragma once

#include <memory>

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
class IVirtualDatabase {
public:
  using Ref = std::shared_ptr<IVirtualDatabase>;
  static Status create(Ref &obj);

  IVirtualDatabase() = default;
  virtual ~IVirtualDatabase() = default;

  virtual Status registerTable(IVirtualTable::Ref table) = 0;

  virtual Status query(IVirtualTable::RowList &row_list,
                       const std::string &query) const = 0;

  IVirtualDatabase(const IVirtualDatabase &other) = delete;
  IVirtualDatabase &operator=(const IVirtualDatabase &other) = delete;
};
} // namespace zeek
