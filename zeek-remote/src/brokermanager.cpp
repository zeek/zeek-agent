/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <poll.h>

#include <boost/lexical_cast.hpp>

#include <caf/node_id.hpp>

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>
#include <broker/error.hh>
#include <broker/status.hh>
#include <broker/status_subscriber.hh>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/sql.h>

#include <zeek-remote/utils.h>

#include "brokermanager.h"
#include "osquery/core/conversions.h"
#include "osquery/core/process.h"

namespace zeek {
struct BrokerManager::PrivateData final {
  // Server address and port, taken from the Zeek configuration file
  std::string server_address;
  std::uint16_t server_port{9999U};

  // A pointer to a shared query manager instance
  IQueryManager::Ref query_manager;

  // Mutex to synchronize threats that check connection state
  mutable osquery::Mutex connection_mutex;

  // The IP and port of the remote endpoint
  std::pair<std::string, int> remote_endpoint{"", 0};

  // The status_subscriber of the endpoint
  std::unique_ptr<broker::status_subscriber> ss{nullptr};

  // The connection status
  broker::status connection_status;

  // The ID identifying the node (private channel)
  std::string nodeID;

  // The groups of the node
  std::vector<std::string> groups;

  // The Broker Endpoint
  std::unique_ptr<broker::endpoint> ep{nullptr};

  //  Key: topic_Name, Value: subscriber
  std::map<std::string, std::shared_ptr<broker::subscriber>> subscribers;

  // Initialized from the configuration file
  std::vector<std::string> startup_groups;
};

BrokerManager::BrokerManager(const std::string& server_address,
                             std::uint16_t server_port,
                             const std::vector<std::string>& server_group_list,
                             IQueryManager::Ref query_manager)
    : d(new PrivateData) {
  d->server_address = server_address;
  d->server_port = server_port;
  d->startup_groups = server_group_list;
  d->query_manager = query_manager;

  // Set Broker UID
  auto ident = osquery::getHostIdentifier();
  setNodeID(ident);

  const auto& uid = getNodeID();

  // Read remote endpoint from config
  d->remote_endpoint =
      std::pair<std::string, int>(d->server_address, d->server_port);

  // Create Broker endpoint
  auto s = createEndpoint(uid);
  if (!s.ok()) {
    LOG(ERROR) << "Failed to create broker endpoint";
    throw std::runtime_error{"Broker endpoint cannot be created"};
  }
}

BrokerManager::~BrokerManager() {
  // Shutdown the endpoint
  if (d->ep != nullptr) {
    d->ep->shutdown();
  }
}

osquery::Status BrokerManager::reset(bool groups_only) {
  // Unsubscribe from all groups
  std::vector<std::string> cp_groups(d->groups);
  for (const auto& g : cp_groups) {
    auto s = removeGroup(g);
    if (not s.ok()) {
      return s;
    }
  }

  if (groups_only) {
    return osquery::Status::success();
  }

  // Remove all remaining message queues (manually added)
  std::map<std::string, std::shared_ptr<broker::subscriber>> cp_queues{
      d->subscribers};
  for (const auto& q : cp_queues) {
    auto s = deleteSubscriber(q.first);
    if (not s.ok()) {
      return s;
    }
  }

  return osquery::Status::success();
}

osquery::Status BrokerManager::setNodeID(const std::string& uid) {
  if (!d->nodeID.empty()) {
    return osquery::Status::failure("Node ID already set to '" + d->nodeID +
                                    "' (new: '" + uid + "')");
  }

  // Save new node ID
  d->nodeID = uid;
  return osquery::Status::success();
}

std::string BrokerManager::getNodeID() {
  return d->nodeID;
}

osquery::Status BrokerManager::addGroup(const std::string& group) {
  auto s = createSubscriber(BrokerTopics::PRE_GROUPS + group);
  if (not s.ok()) {
    return s;
  }
  d->groups.push_back(group);
  return osquery::Status::success();
}

osquery::Status BrokerManager::removeGroup(const std::string& group) {
  auto element_pos = std::find(d->groups.begin(), d->groups.end(), group);
  // Group exists?
  if (element_pos == d->groups.end()) {
    return osquery::Status::failure("Group '" + group + "' does not exist");
  }

  // Delete Group
  d->groups.erase(element_pos);

  // Delete message queue (maybe)
  if (std::find(d->groups.begin(), d->groups.end(), group) != d->groups.end()) {
    return osquery::Status(
        0, "More subscriptions for group '" + group + "' exist");
  }

  return deleteSubscriber(BrokerTopics::PRE_GROUPS + group);
}

std::vector<std::string> BrokerManager::getGroups() {
  return d->groups;
}

osquery::Status BrokerManager::createEndpoint(const std::string& ep_name) {
  if (d->ep != nullptr) {
    return osquery::Status::failure("Broker Endpoint already exists");
  }

  VLOG(1) << "Creating broker endpoint for name: " << ep_name;
  d->ep = std::make_unique<broker::endpoint>();
  return osquery::Status::success();
}

osquery::Status BrokerManager::createSubscriber(const std::string& topic) {
  if (d->ep == nullptr) {
    return osquery::Status::failure("Broker Endpoint does not exist");
  }

  if (d->subscribers.count(topic) != 0) {
    return osquery::Status::failure("Message queue exists for topic '" + topic +
                                    "'");
  }

  VLOG(1) << "Creating message queue: " << topic;
  d->subscribers[topic] =
      std::make_shared<broker::subscriber>(d->ep->make_subscriber({topic}));

  return osquery::Status::success();
}

osquery::Status BrokerManager::deleteSubscriber(const std::string& topic) {
  if (d->subscribers.count(topic) == 0) {
    return osquery::Status::failure("Message queue does not exist for topic '" +
                                    topic + "'");
  }

  // shared_ptr should delete the message_queue and unsubscribe from topic
  auto subscriber = d->subscribers.find(topic);
  subscriber->second->remove_topic(topic);
  d->subscribers.erase(subscriber);
  return osquery::Status::success();
}

std::shared_ptr<broker::subscriber> BrokerManager::getSubscriber(
    const std::string& topic) {
  return d->subscribers.at(topic);
}

std::vector<std::string> BrokerManager::getTopics() {
  std::vector<std::string> topics;
  for (const auto& mq : d->subscribers) {
    topics.push_back(mq.first);
  }
  return topics;
}

osquery::Status BrokerManager::checkConnection(long timeout) {
  // Exclusive access
  osquery::WriteLock lock(d->connection_mutex);
  osquery::Status s;

  // Initiate peering?
  if (d->ss == nullptr) {
    // Initial state when connecting
    s = initiateReset(false);
    if (!s.ok()) {
      LOG(WARNING) << s.getMessage();
    }

    VLOG(1) << "Initializing Peering";
    d->ss = std::make_unique<broker::status_subscriber>(
        d->ep->make_status_subscriber(true));
    s = initiatePeering();
  }

  // Was connected last time we checked?
  if (d->connection_status.code() == broker::sc::peer_added) {
    // Any pending status changes?
    if (d->ss->available()) {
      // Reset before processing changes
      s = initiateReset();
      if (!s.ok()) {
        LOG(WARNING) << s.getMessage();
      }
    } else {
      // Still connected since last time
      return osquery::Status::success();
    }
  }

  // Wait for connection to be (re-)established
  getPeeringStatus(0);
  while (d->connection_status.code() != broker::sc::peer_added) {
    // Wait for changes
    getPeeringStatus(timeout);

    // Cancel waiting because of finite timeout
    if (d->connection_status.code() != broker::sc::peer_added && timeout >= 0) {
      // Anyway, peering still continues in the background!
      return osquery::Status::failure("Peering timeout for broker connection");
    }
  }

  // Became successfully connected!
  VLOG(1) << "Broker connection established";
  s = announce();
  if (!s.ok()) {
    LOG(ERROR) << s.getMessage();
    return s;
  }

  return s;
}

osquery::Status BrokerManager::initiatePeering() {
  auto ip = d->remote_endpoint.first;
  auto port = d->remote_endpoint.second;
  LOG(INFO) << "Connecting to Bro " << ip << ":" << port;

  // This call tries to reconnect every X seconds automatically
  d->ep->peer_nosync(ip, port, broker::timeout::seconds(3));

  return osquery::Status::success();
}

osquery::Status BrokerManager::initiateReset(bool reset_schedule) {
  // Reset queries, schedule and broker
  d->query_manager->reset();
  if (reset_schedule) {
    d->query_manager->updateSchedule();
  }

  reset(false);

  // Subscribe to all
  auto s = createSubscriber(BrokerTopics::ALL);
  if (!s.ok()) {
    return s;
  }
  // Subscribe to individual topic
  s = createSubscriber(BrokerTopics::PRE_INDIVIDUALS + getNodeID());
  if (!s.ok()) {
    return s;
  }
  // Set Startup groups and subscribe to group topics
  for (const auto& g : d->startup_groups) {
    s = addGroup(g);
    if (!s.ok()) {
      return s;
    }
  }

  return osquery::Status::success();
}

std::pair<broker::status, bool> BrokerManager::getPeeringStatus(long timeout) {
  // Process latest status changes
  caf::variant<broker::none, broker::error, broker::status> s;
  bool has_changed = false;

  // Block first to wait for a status change to happen
  if (timeout != 0) {
    // with timeout
    if (timeout > 0) {
      if (auto s_opt = d->ss->get(broker::to_duration(timeout))) {
        // Status received in time
        s = s_opt.value();
      }
    } else {
      // block until status change
      s = d->ss->get();
    }
  }

  // Process any remaining change that is queued
  while (d->ss->available()) {
    s = d->ss->get();
  }

  // Evaluate the latest change (if any)
  // Check error
  if (auto err = broker::get_if<broker::error>(s)) {
    LOG(WARNING) << "Broker error:" << static_cast<int>(err->code()) << ", "
                 << to_string(*err);
    d->connection_status = {};
    has_changed = true;
  }
  // Check status
  if (auto st = broker::get_if<broker::status>(s)) {
    VLOG(1) << "Broker status:" << static_cast<int>(st->code()) << ", "
            << to_string(*st);
    d->connection_status = *st;
    has_changed = true;
  }
  // Check none
  if (auto st = broker::get_if<broker::none>(s)) {
    // No event, there was nothing
  }

  return {d->connection_status, has_changed};
}

osquery::Status BrokerManager::announce() {
  // Announce this endpoint to be a bro-osquery extension
  // Collect Groups
  broker::vector group_list;
  for (const auto& g : getGroups()) {
    group_list.push_back(broker::data(g));
  }

  // Create Message
  broker::bro::Event announceMsg(
      BrokerEvents::HOST_NEW,
      {broker::data(caf::to_string(d->ep->node_id())),
       broker::data(getNodeID()),
       group_list});
  auto s = sendEvent(BrokerTopics::ANNOUNCE, announceMsg);
  if (!s.ok()) {
    return s;
  }

  return osquery::Status::success();
}

int BrokerManager::getOutgoingConnectionFD() {
  if (d->ep == nullptr) {
    return -1;
  }
  return d->ss->fd();
}

osquery::Status BrokerManager::logQueryLogItemToZeek(
    const osquery::QueryLogItem& qli) {
  const auto& queryID = qli.name;

  // Is this schedule or one-time? Get Query and Type
  std::string query = "";
  std::string qType = "";
  auto status_find = d->query_manager->findQueryAndType(queryID, qType, query);
  if (!status_find.ok()) {
    // Might have been unsubscribed from during query execution
    LOG(WARNING) << "Cannot send query results to Bro: "
                 << status_find.getMessage();
    return osquery::Status::success();
  }

  // Rows to be reported
  std::vector<std::tuple<osquery::Row, std::string>> rows;
  for (const auto& row : qli.results.added) {
    rows.emplace_back(row, "ADD");
  }
  for (const auto& row : qli.results.removed) {
    rows.emplace_back(row, "REMOVE");
  }
  for (const auto& row : qli.snapshot_results) {
    rows.emplace_back(row, "SNAPSHOT");
  }

  // Get Info about SQL Query and Types
  osquery::TableColumns columns;
  auto status = getQueryColumns(query, columns);
  if (!status.ok()) {
    LOG(ERROR) << status.getMessage();
    osquery::Initializer::requestShutdown(status.getCode());
    return status;
  }

  std::map<std::string, osquery::ColumnType> columnTypes;
  for (const auto& t : columns) {
    const auto& columnName = std::get<0>(t);
    const auto& columnType = std::get<1>(t);
    columnTypes[columnName] = columnType;
  }

  // Common message fields
  const auto& uid = getNodeID();
  const auto& topic = d->query_manager->getEventTopic(queryID);
  const auto& event_name = d->query_manager->getEventName(queryID);
  VLOG(1) << "Creating " << rows.size() << " messages with event name '"
          << event_name << " (ID " << queryID << ")";

  // Create message for each row
  for (const auto& element : rows) {
    // Get row and trigger
    const auto& row = std::get<0>(element);
    const auto& trigger = std::get<1>(element);

    // Create message data header
    broker::vector msg_data;
    broker::vector result_info(
        {broker::data(uid),
         broker::data(broker::data(broker::enum_value{"osquery::" + trigger})),
         broker::data(d->query_manager->getEventCookie(queryID))});
    msg_data.push_back(broker::data(result_info));

    // Format each column
    for (const auto& t : columns) {
      const auto& colName = std::get<0>(t);
      if (row.count(colName) != 1) {
        LOG(ERROR) << "Column '" << colName << "' not present in results for '"
                   << event_name << "'";
        std::string av_names;
        for (const auto& an : row) {
          if (av_names.empty())
            av_names += std::get<0>(an);
          else
            av_names += ", " + std::get<0>(an);
        }
        LOG(ERROR) << "Available column names: " << av_names;
        break;
      }
      const auto& value = row.at(colName);

      try {
        switch (columnTypes.at(colName)) {
        case osquery::ColumnType::UNKNOWN_TYPE: {
          LOG(WARNING) << "Sending unknown column type for column '" + colName +
                              "' as string";
          msg_data.push_back(broker::data(value));
          break;
        }
        case osquery::ColumnType::TEXT_TYPE: {
          msg_data.push_back(broker::data(value));
          break;
        }
        case osquery::ColumnType::INTEGER_TYPE: {
          auto lexpr = osquery::tryTo<INTEGER_LITERAL>(value);
          if (lexpr) {
            msg_data.push_back(broker::data(lexpr.take()));
          }
          break;
        }
        case osquery::ColumnType::BIGINT_TYPE: {
          auto lexpr = osquery::tryTo<BIGINT_LITERAL>(value);
          if (lexpr) {
            msg_data.push_back(broker::data(lexpr.take()));
          }
          break;
        }
        case osquery::ColumnType::UNSIGNED_BIGINT_TYPE: {
          auto lexpr = osquery::tryTo<UNSIGNED_BIGINT_LITERAL>(value);
          if (lexpr) {
            msg_data.push_back(broker::data(lexpr.take()));
          }
          break;
        }
        case osquery::ColumnType::DOUBLE_TYPE: {
          char* end = nullptr;
          double afinite = strtod(value.c_str(), &end);
          if (end == nullptr || end == value.c_str() || *end != '\0') {
          } else {
            msg_data.push_back(broker::data(afinite));
          }
          break;
        }
        case osquery::ColumnType::BLOB_TYPE: {
          LOG(WARNING) << "Sending blob column type for column '" + colName +
                              "' as string";
          msg_data.push_back(broker::data(value));
          break;
        }
        default: {
          LOG(WARNING) << "Unknown ColumnType for column '" + colName + "'";
          continue;
        }
        }
      } catch (const boost::bad_lexical_cast& e) {
        LOG(ERROR) << "Skip result for query ID '" << queryID
                   << "' because value '" << value << "' (Column: " << colName
                   << ") cannot be parsed as '"
                   << osquery::kColumnTypeNames.at(columnTypes.at(colName))
                   << '"';
        break;
      }
    }

    // Send event message
    broker::bro::Event msg(event_name, msg_data);
    sendEvent(topic, msg);
  }

  // Delete one-time query information
  if (qType == "ONETIME") {
    d->query_manager->removeQueryEntry(query);
  }

  return osquery::Status::success();
}

osquery::Status BrokerManager::sendEvent(const std::string& topic,
                                         const broker::bro::Event& msg) {
  if (d->ep == nullptr) {
    return osquery::Status::failure("Endpoint not set");
  } else {
    VLOG(1) << "Sending Message '" << msg.name() << "' to  topic '" << topic
            << "'";
    d->ep->publish(topic, msg);
  }

  return osquery::Status::success();
}

osquery::Status IBrokerManager::create(
    Ref& ref,
    const std::string& server_address,
    std::uint16_t server_port,
    const std::vector<std::string>& server_group_list,
    IQueryManager::Ref query_manager) {
  try {
    ref.reset();

    auto ptr = new BrokerManager(
        server_address, server_port, server_group_list, query_manager);

    ref.reset(ptr);

    return osquery::Status::success();

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure(
        "Failed to create the BrokerManager object");

  } catch (const osquery::Status& status) {
    return status;
  }
}
} // namespace zeek
