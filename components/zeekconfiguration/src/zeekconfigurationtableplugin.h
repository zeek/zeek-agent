#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeekconfiguration.h>

namespace zeek {
class ZeekConfigurationTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(Ref &obj, IZeekConfiguration &configuration);
  virtual ~ZeekConfigurationTablePlugin() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

protected:
  ZeekConfigurationTablePlugin(IZeekConfiguration &configuration);

public:
  static Status generateRow(Row &row);
};
} // namespace zeek
