/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "zeekdistributedplugin.h"
#include "globals.h"

#include <poll.h>

#include <sstream>
#include <vector>

#include <boost/property_tree/ptree.hpp>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/distributed.h>
#include <osquery/enroll.h>
#include <osquery/flags.h>
#include <osquery/registry.h>

#include <broker/bro.hh>

#include <zeek-remote/utils.h>

#include "osquery/core/json.h"
#include "osquery/remote/serializers/json.h"
#include "osquery/remote/utility.h"

namespace pt = boost::property_tree;

namespace zeek {
namespace {
/**
 * @brief process a broker message that was received on the main-server-loop
 *
 * The messages actions depends on its message type.
 *
 *  EVENT_HOST_JOIN: Makes the osquery host to join a group (subscribe to broker
 * topic) utilizing BrokerManager
 *  EVENT_HOST_LEAVE: Makes the osquery host to leave a group (unsubscribe from
 * broker topic) utilizing BrokerManager
 *  EVENT_HOST_EXECUTE: add the query to the vector oT_queries and keep track
 * utilizing QueryManager
 *  EVENT_HOST_SUBSCRIBE: add the query to schedule of osquery daemon utilizing
 * the QueryManager
 *  EVENT_HOST_UNSUBSCRIBE: remove the query from schedule of osquery daemon
 * utilizing the QueryManager
 *
 * @param event the broker message
 * @param topic the topic where the broker message was received on
 * @param oT_queries a vector to append one-time queries to
 * @return
 */
osquery::Status processMessage(
    const broker::bro::Event& event,
    const std::string& topic,
    std::vector<osquery::DistributedQueryRequest>& oT_queries) {
  auto event_args = event.args();

  // Check Event Type
  if (event.name().empty()) {
    return osquery::Status::failure("No or invalid event name '" +
                                    event.name() + "'when processing message");
  }

  LOG(INFO) << "Received event '" << event.name() << "' on topic '" << topic
            << "'";

  if (event.name() == BrokerEvents::HOST_EXECUTE) {
    // One-Time Query Execution
    SubscriptionRequest sr;
    createSubscriptionRequest(BrokerRequestType::EXECUTE, event, topic, sr);

    std::string newQID = query_manager->addOneTimeQueryEntry(sr);
    if (newQID.empty()) {
      return osquery::Status::failure("Unable to add Broker Query Entry");
    }

    osquery::DistributedQueryRequest dqr;
    dqr.id = newQID;
    dqr.query = sr.query;
    oT_queries.push_back(dqr);

    return osquery::Status::success();

  } else if (event.name() == BrokerEvents::HOST_SUBSCRIBE) {
    // New SQL Query Request
    SubscriptionRequest sr;
    createSubscriptionRequest(BrokerRequestType::SUBSCRIBE, event, topic, sr);

    auto s = query_manager->addScheduleQueryEntry(sr);
    if (!s.ok()) {
      return s;
    }

  } else if (event.name() == BrokerEvents::HOST_UNSUBSCRIBE) {
    // SQL Query Cancel
    SubscriptionRequest sr;
    createSubscriptionRequest(BrokerRequestType::UNSUBSCRIBE, event, topic, sr);
    std::string query = sr.query;

    // Use the exact sql string as UNIQUE identifier for identifying a query
    auto s = query_manager->removeQueryEntry(query);
    if (!s.ok()) {
      return s;
    }

  } else if (event.name() == BrokerEvents::HOST_JOIN) {
    if (event_args.size() != 1) {
      return osquery::Status::failure("Unable to parse message '" +
                                      event.name() + "'");
    }

    if (auto newGroup = broker::get_if<std::string>(event_args[0])) {
      return broker_manager->addGroup(*newGroup);
    }

    return osquery::Status::failure("Unable to parse message '" + event.name() +
                                    "'");

  } else if (event.name() == BrokerEvents::HOST_LEAVE) {
    if (event_args.size() != 1) {
      return osquery::Status::failure("Unable to parse message '" +
                                      event.name() + "'");
    }

    if (auto newGroup = broker::get_if<std::string>(event_args[0])) {
      return broker_manager->removeGroup(*newGroup);
    }

    return osquery::Status::failure("Unable to parse message '" + event.name() +
                                    "'");

  } else {
    // Unkown Message
    return osquery::Status::failure("Unknown event name '" + event.name() +
                                    "'");
  }

  // Apply to new config/schedule
  query_manager->updateSchedule();

  return osquery::Status::success();
}
} // namespace

osquery::Status ZeekDistributedPlugin::setUp() {
  LOG(INFO) << "Starting the Zeek Distributed Plugin";

  auto status = initializeGlobals();
  if (!status.ok()) {
    return status;
  }

  // Initiate Peering
  broker_manager->checkConnection(0);

  return osquery::Status::success();
}

osquery::Status ZeekDistributedPlugin::getQueries(std::string& json) {
  // Check for connection failure and wait for repair
  auto s = broker_manager->checkConnection();
  if (!s.ok()) {
    LOG(WARNING) << "Unable to repair broker connection";
    return s;
  }

  // Collect all topics and subscribers
  std::vector<std::string> topics = broker_manager->getTopics();

  // Retrieve info about each subscriber and the file descriptor
  std::unique_ptr<pollfd[]> fds(new pollfd[topics.size() + 1]);

  for (unsigned long i = 0; i < topics.size(); i++) {
    BrokerSubscriberRef subscriber_ref = {};
    s = broker_manager->getSubscriber(subscriber_ref, topics.at(i));
    if (!s.ok()) {
      continue;
    }

    fds[i] = pollfd{subscriber_ref->fd(), POLLIN | POLLERR, 0};
  }

  // Append the connection status file descriptor to detect connection failures
  fds[topics.size()] =
      pollfd{broker_manager->getOutgoingConnectionFD(), POLLIN | POLLERR, 0};

  assert(broker_manager->getOutgoingConnectionFD() > 0);

  // Wait for incoming message
  poll(fds.get(), topics.size() + 1, -1);

  // Collect OneTime Queries
  std::vector<osquery::DistributedQueryRequest> oT_queries;

  // Check for the socket where a message arrived on
  for (unsigned long i = 0; i < topics.size(); i++) {
    if (fds[i].revents == 0) {
      // Nothing to do for this socket
      continue;
    }
    // Pick topic of the respective socket
    const auto& topic = topics.at(i);

    if ((fds[i].revents & POLLERR) == POLLERR) {
      // Error on this socket
      LOG(WARNING) << "Poll error on fd of queue for topic '" << topic << "'";
      continue;
    }

    BrokerSubscriberRef subscriber_ref = {};
    s = broker_manager->getSubscriber(subscriber_ref, topic);
    if (!s.ok()) {
      LOG(WARNING) << s.getMessage();
      continue;
    }

    // Process each message on this socket
    for (const auto& msg : subscriber_ref->poll()) {
      // Directly updates the daemon schedule if requested
      // Returns one time queries otherwise
      assert(topic == msg.first);

      broker::bro::Event event(msg.second);
      s = processMessage(event, topic, oT_queries);
      if (!s.ok()) {
        LOG(ERROR) << s.getMessage();
        continue;
      }
    }
  }

  // Check the broker connection
  if (fds[topics.size()].revents == 1) {
    VLOG(1) << "Break fd loop because broker connection changed";
  }

  // Serialize the distributed query requests
  s = serializeDistributedQueryRequestsJSON(oT_queries, json);

  // VLOG(1) << "Serialized execution queries: " << json;
  if (!s.ok()) {
    LOG(ERROR) << s.getMessage();
    return s;
  }

  return osquery::Status::success();
}

osquery::Status ZeekDistributedPlugin::writeResults(const std::string& json) {
  // Parse json
  // VLOG(1) << "Serialized execution query results: " << json;
  std::vector<std::pair<std::string, std::pair<osquery::QueryData, int>>>
      query_results;
  parseDistributedQueryResultsJSON(json, query_results);

  // For each query
  for (const auto& query_result : query_results) {
    // Get the query ID
    std::string queryID = query_result.first;
    VLOG(1) << "Writing results for onetime query with ID '" << queryID << "'";

    // Get the query data
    auto results = query_result.second.first;

    // Get Query Info from QueryManager
    std::string response_event = query_manager->getEventName(queryID);
    std::string queryName, qType;
    query_manager->findQueryAndType(queryID, qType, queryName);

    // Any results for this query?
    if (results.empty()) {
      VLOG(1) << "One-time query '" << response_event << "' has no results";
      query_manager->removeQueryEntry(queryName);
      return osquery::Status::success();
    }

    // Assemble a response item (as snapshot)
    osquery::QueryLogItem item;
    item.name = queryID;
    item.identifier = osquery::getHostIdentifier();
    item.time = osquery::getUnixTime();
    item.calendar_time = osquery::getAsciiTime();
    item.snapshot_results = results;

    // Send snapshot to the logger
    std::string registry_name = "logger";
    std::string item_name = "zeek_logger";
    std::string json_str;
    serializeQueryLogItemJSON(item, json_str);

    osquery::PluginRequest request = {{"snapshot", json_str},
                                      {"category", "event"}};
    auto s = osquery::Registry::call(registry_name, item_name, request);
    if (!s.ok()) {
      return s;
    }
  }

  return osquery::Status::success();
}
} // namespace zeek