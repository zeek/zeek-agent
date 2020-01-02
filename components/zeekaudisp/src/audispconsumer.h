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
/// \brief Audisp socket consumer (implementation)
class AudispConsumer final : public IAudispConsumer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param audisp_producer An initialized Audisp socket reader
  /// \return A Status object
  static Status createWithProducer(Ref &obj,
                                   IAudispProducer::Ref audisp_producer);

  /// \brief Destructor
  virtual ~AudispConsumer() override;

  /// \brief At each new call, it will read and process data from the audisp
  /// producer \return A Status object
  virtual Status processEvents() override;

  /// \brief Returns the processed events
  /// \param event_list Where the event list is stored
  /// \return A Status object
  virtual Status getEvents(AuditEventList &event_list) override;

protected:
  /// \brief Constructor
  /// \param audisp_producer An initialized Audisp socket reader
  AudispConsumer(IAudispProducer::Ref audisp_producer);

private:
  /// \brief Callback dispatcher for libauparse
  /// \param event_type Contains the reason for the invocation
  /// \param user_data Contains a reference to an AudispConsumer instance
  static void auparseCallbackDispatcher(auparse_state_t *,
                                        auparse_cb_event_t event_type,
                                        void *user_data);

  /// \brief auparse callback, invoked by auparseCallbackDispatcher
  /// \param event_type Contains the reason for the invocation
  void auparseCallback(auparse_cb_event_t event_type);

public:
  /// \brief Parses a SYSCALL record
  /// \param data Where the parsed data is stored
  /// \param auparse The auparse library interface
  /// \return A Status object
  static Status parseSyscallRecord(std::optional<SyscallRecordData> &data,
                                   IAuparseInterface::Ref auparse);

  /// \brief Parses an EXECVE record
  /// \param data Where the parsed data is stored
  /// \param auparse The auparse library interface
  /// \return A Status object
  static Status parseRawExecveRecord(RawExecveRecordData &raw_data,
                                     IAuparseInterface::Ref auparse);

  /// \brief Assembles multiple raw EXECVE records into one
  /// \param data Where the processed data is stored
  /// \param raw_data The list of raw EXECVE records
  /// \return A Status object
  static Status processExecveRecords(ExecveRecordData &data,
                                     RawExecveRecordData &raw_data);

  /// \brief Parses a CWD record
  /// \param data Where the parsed data is stored
  /// \param auparse The auparse library interface
  /// \return A Status object
  static Status parseCwdRecord(std::string &data,
                               IAuparseInterface::Ref auparse);

  /// \brief Parses a PATH record
  /// \param data Where the parsed data is stored
  /// \param auparse The auparse library interface
  /// \return A Status object
  static Status parsePathRecord(PathRecordData &data,
                                IAuparseInterface::Ref auparse);

  /// \brief Parses a SOCKADDR record
  /// \param data Where the parsed data is stored
  /// \param auparse The auparse library interface
  /// \return A Status object
  static Status parseSockaddrRecord(SockaddrRecordData &data,
                                    IAuparseInterface::Ref auparse);

  friend class IAudispConsumer;
};
} // namespace zeek
