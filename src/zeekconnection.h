#pragma once

#include "queryscheduler.h"

#include <memory>
#include <optional>

#include <broker/broker.hh>

#include <zeek/status.h>

namespace zeek {
class ZeekConnection final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using Ref = std::unique_ptr<ZeekConnection>;

  static Status create(Ref &obj);
  ~ZeekConnection();

  Status joinGroup(const std::string &name);
  Status leaveGroup(const std::string &name);

  Status processEvents();
  QueryScheduler::TaskQueue getTaskQueue();

  Status processTaskOutputList(QueryScheduler::TaskOutputList task_output_list);

  ZeekConnection(const ZeekConnection &) = delete;
  ZeekConnection &operator=(const ZeekConnection &) = delete;

private:
  ZeekConnection();

  broker::configuration getBrokerConfiguration();
  Status createSubscription(const std::string &topic);
  Status destroySubscription(const std::string &topic);

  using StatusEventList = std::vector<broker::sc>;
  Status getStatusEvents(StatusEventList &status_event_list);

  Status waitForActivity(bool &ready);
  Status processTaskOutput(const QueryScheduler::TaskOutput &task_output);

  void publishTaskOutput(const std::string &trigger,
                         const std::string &response_topic,
                         const std::string &response_event,
                         const std::string &cookie,
                         const IVirtualDatabase::QueryOutput &query_output);

public:
  using DifferentialData =
      std::unordered_map<std::uint64_t, IVirtualDatabase::OutputRow>;

  using DifferentialContext = std::unordered_map<std::string, DifferentialData>;

  struct DifferentialOutput final {
    IVirtualDatabase::QueryOutput added_row_list;
    IVirtualDatabase::QueryOutput removed_row_list;
  };

  static Status computeQueryOutputHash(std::uint64_t &hash,
                                       const IVirtualDatabase::OutputRow &row);

  static std::string computeQueryID(const std::string &response_topic,
                                    const std::string &response_event,
                                    const std::string &cookie);

  static Status
  computeDifferentials(DifferentialContext &context, DifferentialOutput &output,
                       const QueryScheduler::TaskOutput &task_output);

  static std::string getHostIdentifier();

  static Status scheduledTaskFromZeekEvent(QueryScheduler::Task &task,
                                           const broker::zeek::Event &event);

  static Status oneShotTaskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event);

  static Status taskFromZeekEvent(QueryScheduler::Task &task,
                                  const broker::zeek::Event &event);
};
} // namespace zeek
