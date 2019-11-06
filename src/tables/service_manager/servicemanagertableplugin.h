#pragma once

#include "servicemanager.h"

#include <zeek/ivirtualtable.h>

namespace zeek {
class ServiceManagerTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(Ref &obj, ServiceManager &service_manager);
  virtual ~ServiceManagerTablePlugin() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

protected:
  ServiceManagerTablePlugin(ServiceManager &service_manager);
};
} // namespace zeek
