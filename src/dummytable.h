#pragma once

#include <zeek/ivirtualtable.h>

namespace zeek {
class DummyTable final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using Ref = std::unique_ptr<DummyTable>;

  static Status create(Ref &obj);
  virtual ~DummyTable() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

protected:
  DummyTable();
};
} // namespace zeek
