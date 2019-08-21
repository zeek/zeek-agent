#pragma once

#include <zeek/ivirtualdatabase.h>

namespace zeek {
class VirtualDatabase final : public IVirtualDatabase {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  virtual ~VirtualDatabase() override;

  virtual Status registerTable(IVirtualTable::Ref table) override;

  virtual Status query(IVirtualTable::RowList &row_list,
                       const std::string &query) const override;

protected:
  VirtualDatabase();

  friend class IVirtualDatabase;

public:
  static Status validateTableName(const std::string &name);
  static Status validateTableSchema(const IVirtualTable::Schema &schema);
};
} // namespace zeek
