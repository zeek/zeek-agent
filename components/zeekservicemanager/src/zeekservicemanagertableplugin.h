#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeekservicemanager.h>

namespace zeek {
class ZeekServiceManagerTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(Ref &obj, IZeekServiceManager &service_manager);
  virtual ~ZeekServiceManagerTablePlugin() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

protected:
  ZeekServiceManagerTablePlugin(IZeekServiceManager &service_manager);
};
} // namespace zeek
