#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeeklogger.h>

namespace zeek {
class OsqueryTablePlugin final : public IVirtualTable {
public:
  static Status create(Ref &ref, const std::string &osquery_table_name,
                       IZeekLogger &logger);
  virtual ~OsqueryTablePlugin() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

protected:
  OsqueryTablePlugin(const std::string &osquery_table_name,
                     IZeekLogger &logger);

  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace zeek
