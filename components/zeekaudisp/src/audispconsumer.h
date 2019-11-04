#pragma once

#include "audispconsumer.h"
#include "iaudispproducer.h"
#include "iauparseinterface.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

#include <zeek/iaudispconsumer.h>

namespace zeek {
class AudispConsumer final : public IAudispConsumer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status createWithProducer(Ref &obj,
                                   IAudispProducer::Ref audisp_producer);
  virtual ~AudispConsumer() override;

  virtual Status processEvents() override;
  virtual Status getEvents(AuditEventList &event_list) override;

protected:
  AudispConsumer(IAudispProducer::Ref audisp_producer);

private:
  static void auparseCallbackDispatcher(auparse_state_t *,
                                        auparse_cb_event_t event_type,
                                        void *user_data);
  void auparseCallback(auparse_cb_event_t event_type);

public:
  static Status parseSyscallRecord(std::optional<SyscallRecordData> &data,
                                   IAuparseInterface::Ref auparse);

  static Status parseRawExecveRecord(RawExecveRecordData &raw_data,
                                     IAuparseInterface::Ref auparse);

  static Status processExecveRecords(ExecveRecordData &data,
                                     RawExecveRecordData &raw_data);

  static Status parseCwdRecord(std::string &data,
                               IAuparseInterface::Ref auparse);

  static Status parsePathRecord(PathRecordData &data,
                                IAuparseInterface::Ref auparse);

  friend class IAudispConsumer;
};
} // namespace zeek
