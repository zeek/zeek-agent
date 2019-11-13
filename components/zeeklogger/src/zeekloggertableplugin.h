#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeeklogger.h>

namespace zeek {
class ZeekLoggerTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(Ref &obj);
  virtual ~ZeekLoggerTablePlugin() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

  Status appendMessage(IZeekLogger::Severity severity,
                       const std::string &message);

protected:
  ZeekLoggerTablePlugin();

public:
  static Status generateRow(Row &row, IZeekLogger::Severity severity,
                            const std::string &message);
};
} // namespace zeek
