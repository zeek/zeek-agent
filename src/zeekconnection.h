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

public:
  static const std::string BrokerTopic_ALL;
  static const std::string BrokerTopic_ANNOUNCE;
  static const std::string BrokerTopic_PRE_INDIVIDUALS;
  static const std::string BrokerTopic_PRE_GROUPS;
  static const std::string BrokerTopic_PRE_CUSTOMS;
  static const std::string BrokerEvent_HOST_NEW;
  static const std::string BrokerEvent_HOST_EXECUTE;

  static std::string getHostIdentifier();

  static Status scheduledTaskFromZeekEvent(QueryScheduler::Task &task,
                                           const broker::zeek::Event &event);

  static Status oneShotTaskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event);

  static Status taskFromZeekEvent(QueryScheduler::Task &task,
                                  const broker::zeek::Event &event);
};
} // namespace zeek
