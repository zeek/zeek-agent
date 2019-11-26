#pragma once

#include <memory>
#include <vector>

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
class IVirtualDatabase {
public:
  struct ColumnValue final {
    std::string name;
    IVirtualTable::OptionalVariant data;
  };

  using OutputRow = std::vector<ColumnValue>;
  using QueryOutput = std::vector<OutputRow>;

  using Ref = std::unique_ptr<IVirtualDatabase>;
  static Status create(Ref &obj);

  IVirtualDatabase() = default;
  virtual ~IVirtualDatabase() = default;

  virtual std::vector<std::string> virtualTableList() const = 0;
  virtual Status registerTable(IVirtualTable::Ref table) = 0;
  virtual Status unregisterTable(const std::string &name) = 0;

  virtual Status query(QueryOutput &output, const std::string &query) const = 0;

  IVirtualDatabase(const IVirtualDatabase &other) = delete;
  IVirtualDatabase &operator=(const IVirtualDatabase &other) = delete;
};
} // namespace zeek
