#include "zeekconnection.h"
#include "configuration.h"
#include "logger.h"

#include <unordered_map>

#include <poll.h>
#include <unistd.h>

#include <broker/endpoint.hh>
#include <broker/zeek.hh>

namespace zeek {
namespace {
const std::string kHostSubscribeEvent{"osquery::host_subscribe"};
const std::string kHostUnsubscribeEvent{"osquery::host_unsubscribe"};

const std::string kHostJoinEvent{"osquery::host_join"};
const std::string kHostLeaveEvent{"osquery::host_leave"};

const std::string kHostExecuteEvent{"osquery::host_execute"};

std::string getSystemHostname() {
  std::vector<char> buffer(1024);
  gethostname(buffer.data(), buffer.size());

  buffer.push_back(0);
  return buffer.data();
}

template <typename FieldType, int field_index>
FieldType getZeekEventField(const broker::zeek::Event &event) {
  const auto &argument_list = event.args();
  if (field_index >= argument_list.size()) {
    throw Status::failure("Field does not exists");
  }

  const auto &argument = argument_list[field_index];
  if (!broker::is<FieldType>(argument)) {
    throw Status::failure("Field is of wrong type");
  }

  return broker::get<FieldType>(argument);
}

auto getZeekEventResponseEventName = getZeekEventField<std::string, 0>;
auto getZeekEventQueryString = getZeekEventField<std::string, 1>;
auto getZeekEventCookie = getZeekEventField<std::string, 2>;
auto getZeekEventResponseTopic = getZeekEventField<std::string, 3>;
auto getZeekEventUpdateType = getZeekEventField<std::string, 4>;
auto getZeekEventInterval = getZeekEventField<std::uint64_t, 5>;
} // namespace

struct ZeekConnection::PrivateData final {
  PrivateData(broker::configuration config)
      : broker_endpoint(new broker::endpoint(std::move(config))),
        status_subscriber(broker_endpoint->make_status_subscriber(true)) {}

  std::unique_ptr<broker::endpoint> broker_endpoint;

  broker::status_subscriber status_subscriber;

  std::unordered_map<std::string, broker::subscriber> subscriber_map;
  std::vector<std::string> joined_group_list;

  QueryScheduler::TaskQueue task_queue;
};

Status ZeekConnection::create(Ref &obj) {
  try {
    obj.reset();

    auto ptr = new ZeekConnection();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

ZeekConnection::~ZeekConnection() { d->broker_endpoint->shutdown(); }

Status ZeekConnection::joinGroup(const std::string &name) {
  auto group_it =
      std::find(d->joined_group_list.begin(), d->joined_group_list.end(), name);

  if (group_it != d->joined_group_list.end()) {
    return Status::failure("The following group has already been joined: " +
                           name);
  }

  auto status = createSubscription(BrokerTopic_PRE_GROUPS + name);
  if (!status.succeeded()) {
    throw status;
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "A new group has been joined: " + name);

  d->joined_group_list.push_back(name);
  return Status::success();
}

Status ZeekConnection::leaveGroup(const std::string &name) {
  auto group_it =
      std::find(d->joined_group_list.begin(), d->joined_group_list.end(), name);

  if (group_it == d->joined_group_list.end()) {
    return Status::failure("The following group has not been joined: " + name);
  }

  auto status = destroySubscription(BrokerTopic_PRE_GROUPS + name);
  if (!status.succeeded()) {
    return status;
  }

  d->joined_group_list.erase(group_it);
  return Status::success();
}

Status ZeekConnection::processEvents() {
  StatusEventList status_event_list;
  auto status = getStatusEvents(status_event_list);
  if (!status.succeeded()) {
    return status;
  }

  if (!status_event_list.empty()) {
    // Whatever happened, we are either disconnected or have just
    // reconnected (in which case we have to reset the connection state)
    return Status::failure("Connection hase been lost or reset");
  }

  bool ready{false};
  status = waitForActivity(ready);
  if (!status.succeeded()) {
    return status;
  }

  if (!ready) {
    return Status::success();
  }

  for (auto &subscriber_p : d->subscriber_map) {
    auto &subscriber = subscriber_p.second;

    for (const auto &message : subscriber.poll()) {
      broker::zeek::Event event(caf::get<1>(message));

      if (event.name() == kHostJoinEvent || event.name() == kHostLeaveEvent) {
        const auto &argument_list = event.args();

        if (argument_list.size() != 1U) {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 "Invalid host_join/host_leave event received "
                                 "(wrong argument count)");

          continue;
        }

        auto group_name_ptr = broker::get_if<std::string>(argument_list[0]);
        if (group_name_ptr == nullptr) {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 "Invalid host_join/host_leave event received "
                                 "(missing or invalid group name)");

          continue;
        }

        const auto &group_name = *group_name_ptr;

        if (event.name() == kHostJoinEvent) {
          status = joinGroup(group_name);
        } else {
          status = leaveGroup(group_name);
        }

        if (!status.succeeded()) {
          getLogger().logMessage(
              IZeekLogger::Severity::Error,
              "Failed to handle host_join/host_leave event: " +
                  status.message());
        }

      } else {
        QueryScheduler::Task pending_task;
        status = taskFromZeekEvent(pending_task, event);
        if (!status.succeeded()) {
          getLogger().logMessage(IZeekLogger::Severity::Error,
                                 status.message());

        } else {
          d->task_queue.push_back(std::move(pending_task));
        }
      }
    }
  }

  return Status::success();
}

QueryScheduler::TaskQueue ZeekConnection::getTaskQueue() {
  auto output = std::move(d->task_queue);
  d->task_queue = {};

  return output;
}

Status ZeekConnection::processTaskOutputList(
    QueryScheduler::TaskOutputList task_output_list) {
  for (const auto &task_output : task_output_list) {
    // Skip one-shot queries for now
    if (task_output.task.type == QueryScheduler::Task::Type::ExecuteQuery) {

      continue;
    }

    const auto &current_task = task_output.task;

    // Hard-code what the previous code called "trigger". We are querying
    // event-based tables now, and differentials make no sense in this case
    std::string trigger{"osquery::ADD"};

    broker::vector message_header(
        {broker::data(getHostIdentifier()),
         broker::data(broker::data(broker::enum_value{trigger})),
         broker::data(current_task.cookie)});

    for (const auto &row : task_output.query_output) {
      broker::vector message_data = {broker::data(message_header)};

      for (const auto &column : row) {
        if (column.data.has_value()) {
          const auto &column_variant = column.data.value();

          if (std::holds_alternative<std::string>(column_variant)) {
            message_data.push_back(
                broker::data(std::get<std::string>(column_variant)));
          } else {
            message_data.push_back(
                broker::data(std::get<std::int64_t>(column_variant)));
          }

        } else {
          // TODO: Add support for NULL
          message_data.push_back(broker::data());
        }
      }

      // clang-format off
      d->broker_endpoint->publish(
        current_task.response_topic,
        broker::zeek::Event(current_task.response_event, message_data)
      );
      // clang-format on
    }
  }

  return Status::success();
}

Status ZeekConnection::waitForActivity(bool &ready) {
  ready = false;

  std::vector<pollfd> poll_fd_list;

  for (const auto &subscriber_p : d->subscriber_map) {
    const auto &subscriber = subscriber_p.second;

    // clang-format off
    poll_fd_list.push_back(
      {
        subscriber.fd(),
        POLLIN | POLLERR,
        0
      }
    );
    // clang-format on
  }

  auto poll_err = poll(poll_fd_list.data(), poll_fd_list.size(), 1000);

  if (poll_err == 0) {
    return Status::success();

  } else if (poll_err == -1) {
    if (errno == EINTR) {
      return Status::success();
    }

    return Status::failure("poll() has failed with error " +
                           std::to_string(errno));
  }

  ready = true;
  return Status::success();
}

ZeekConnection::ZeekConnection()
    : d(new PrivateData(getBrokerConfiguration())) {

  const auto &server_address = getConfig().serverAddress();
  auto server_port = getConfig().serverPort();

  d->broker_endpoint->peer_nosync(server_address, server_port,
                                  broker::timeout::seconds(3));

  bool connected{false};

  for (std::size_t retry = 0U; retry < 5U; ++retry) {
    std::this_thread::sleep_for(std::chrono::seconds(1U));

    StatusEventList status_event_list;
    auto status = getStatusEvents(status_event_list);
    if (!status.succeeded()) {
      throw status;
    }

    for (const auto &status_code : status_event_list) {
      switch (status_code) {
      case broker::sc::peer_added:
        connected = true;
        break;

      case broker::sc::peer_lost:
      case broker::sc::peer_removed:
        connected = false;
        break;

      case broker::sc::unspecified:
      default:
        break;
      }
    }

    if (connected) {
      break;
    }
  }

  if (!connected) {
    throw Status::failure("The connection to the Zeek server timed out");
  }

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Successfully connected to " + server_address + ":" +
                             std::to_string(server_port));

  auto status = createSubscription(BrokerTopic_ALL);
  if (!status.succeeded()) {
    throw status;
  }

  status =
      createSubscription(BrokerTopic_PRE_INDIVIDUALS + getHostIdentifier());

  if (!status.succeeded()) {
    throw status;
  }

  for (const auto &group_name : getConfig().groupList()) {
    status = joinGroup(group_name);
    if (!status.succeeded()) {
      throw status;
    }
  }

  broker::vector joined_group_list;

  for (const auto &group : d->joined_group_list) {
    joined_group_list.push_back(broker::data(group));
  }

  // clang-format off
  broker::zeek::Event message(
    BrokerEvent_HOST_NEW,

    {
      broker::data(caf::to_string(d->broker_endpoint->node_id())),
      broker::data(getHostIdentifier()),
      joined_group_list
    }
  );
  // clang-format on

  d->broker_endpoint->publish(BrokerTopic_ANNOUNCE, message);
}

broker::configuration ZeekConnection::getBrokerConfiguration() {
  auto ca_file_path = getConfig().certificateAuthority();
  auto cert_file_path = getConfig().clientCertificate();
  auto key_file_path = getConfig().clientKey();

  broker::configuration config;

  if (!ca_file_path.empty() && !cert_file_path.empty() &&
      !key_file_path.empty()) {
    config.set("openssl.cafile", ca_file_path);
    config.set("openssl.certificate", cert_file_path);
    config.set("openssl.key", key_file_path);
  }

  return config;
}

Status ZeekConnection::createSubscription(const std::string &topic) {
  if (d->subscriber_map.count(topic) != 0U) {
    return Status::failure(
        "A subscription already exists for the following topic: " + topic);
  }

  auto subscriber = d->broker_endpoint->make_subscriber({topic});
  d->subscriber_map.insert({topic, std::move(subscriber)});

  getLogger().logMessage(IZeekLogger::Severity::Information,
                         "Subscribed to: " + topic);

  return Status::success();
}

Status ZeekConnection::destroySubscription(const std::string &topic) {
  auto subscriber_it = d->subscriber_map.find(topic);
  if (subscriber_it == d->subscriber_map.end()) {
    return Status::failure("The following topic has not been subscribed to: " +
                           topic);
  }

  auto &subscriber = subscriber_it->second;
  subscriber.remove_topic(topic);

  d->subscriber_map.erase(subscriber_it);
  return Status::success();
}

Status ZeekConnection::getStatusEvents(StatusEventList &status_event_list) {
  status_event_list = {};

  auto status_message_list = d->status_subscriber.poll();
  if (status_message_list.empty()) {
    return Status::success();
  }

  for (const auto &status_message : status_message_list) {
    if (const auto &status = caf::get_if<broker::status>(&status_message)) {
      status_event_list.push_back(status->code());
    }

    if (const auto &error = caf::get_if<broker::error>(&status_message)) {
      std::string message = caf::to_string(error->context()).c_str();
      return Status::failure(message);
    }
  }

  return Status::success();
}

std::string ZeekConnection::getHostIdentifier() {
  static const std::string kSystemHostname = getSystemHostname();
  return kSystemHostname;
}

Status
ZeekConnection::scheduledTaskFromZeekEvent(QueryScheduler::Task &task,
                                           const broker::zeek::Event &event) {
  task = {};

  const auto &event_name = event.name();
  if (event_name != kHostSubscribeEvent &&
      event_name != kHostUnsubscribeEvent) {

    return Status::failure(
        "Invalid event type (expected: host_subscribe or host_unsubscribe)");
  }

  task.type = (event.name() == kHostSubscribeEvent)
                  ? QueryScheduler::Task::Type::AddScheduledQuery
                  : QueryScheduler::Task::Type::RemoveScheduledQuery;

  try {
    task.query = getZeekEventQueryString(event);
    task.response_event = getZeekEventResponseEventName(event);
    task.cookie = getZeekEventCookie(event);
    task.response_topic = getZeekEventResponseTopic(event);
    task.interval = getZeekEventInterval(event);

    auto update_type = getZeekEventUpdateType(event);
    if (update_type == "ADDED") {
      task.update_type = QueryScheduler::Task::UpdateType::Added;

    } else if (update_type == "REMOVED") {
      task.update_type = QueryScheduler::Task::UpdateType::Removed;

    } else if (update_type == "BOTH") {
      task.update_type = QueryScheduler::Task::UpdateType::Both;

    } else {
      return Status::failure("Invalid update type for scheduled queries: " +
                             update_type);
    }

    return Status::success();

  } catch (const Status &status) {
    return status;
  }
}

Status
ZeekConnection::oneShotTaskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event) {
  task = {};

  const auto &event_name = event.name();
  if (event_name != kHostExecuteEvent) {
    return Status::failure("Invalid event type (expected: host_execute)");
  }

  try {
    task.type = QueryScheduler::Task::Type::ExecuteQuery;
    task.query = getZeekEventQueryString(event);
    task.response_event = getZeekEventResponseEventName(event);
    task.cookie = getZeekEventCookie(event);
    task.response_topic = getZeekEventResponseTopic(event);

    auto update_type = getZeekEventUpdateType(event);
    if (update_type != "SNAPSHOT") {
      return Status::failure("Invalid update type for one-shot queries: " +
                             update_type);
    }

    return Status::success();

  } catch (const Status &status) {
    return status;
  }
}

Status ZeekConnection::taskFromZeekEvent(QueryScheduler::Task &task,
                                         const broker::zeek::Event &event) {

  const auto &event_name = event.name();

  if (event_name == kHostSubscribeEvent ||
      event_name == kHostUnsubscribeEvent) {

    return scheduledTaskFromZeekEvent(task, event);

  } else if (event_name == kHostExecuteEvent) {
    return scheduledTaskFromZeekEvent(task, event);

  } else {
    task = {};
    return Status::failure("Invalid event name: " + event_name);
  }
}

#define ZEEK_TOPIC_PREFIX "/bro/osquery/"

const std::string ZeekConnection::BrokerTopic_ALL{ZEEK_TOPIC_PREFIX "hosts"};

const std::string ZeekConnection::BrokerTopic_ANNOUNCE{ZEEK_TOPIC_PREFIX
                                                       "host_announce"};

const std::string ZeekConnection::BrokerTopic_PRE_INDIVIDUALS{ZEEK_TOPIC_PREFIX
                                                              "host/"};

const std::string ZeekConnection::BrokerTopic_PRE_GROUPS{ZEEK_TOPIC_PREFIX
                                                         "group/"};

const std::string ZeekConnection::BrokerTopic_PRE_CUSTOMS{ZEEK_TOPIC_PREFIX
                                                          "custom/"};

const std::string ZeekConnection::BrokerEvent_HOST_NEW{"osquery::host_new"};

} // namespace zeek
