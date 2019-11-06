#pragma once

#include <zeek/iaudispconsumer.h>
#include <zeek/ivirtualtable.h>

namespace zeek {
class SocketEventsTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(Ref &obj);
  virtual ~SocketEventsTablePlugin() override;

  virtual const std::string &name() const override;
  virtual const Schema &schema() const override;
  virtual Status generateRowList(RowList &row_list) override;

  Status processEvents(const IAudispConsumer::AuditEventList &event_list);

protected:
  SocketEventsTablePlugin();

public:
  static Status generateRow(Row &row,
                            const IAudispConsumer::AuditEvent &audit_event);
};
} // namespace zeek
