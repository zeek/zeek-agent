/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/trim.hpp>

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/query.h>
#include <osquery/sdk.h>
#include <osquery/sql.h>

#include "osquery/core/json.h"

#include <zeek-remote/utils.h>

namespace zeek {
osquery::Status getOsqueryConfiguration(
    ConfigurationFileMap& configuration_file_map) {
  configuration_file_map.clear();

  osquery::PluginResponse gen_config_response_list;
  auto status = osquery::Registry::call(
      "config", {{"action", "genConfig"}}, gen_config_response_list);

  if (!status.ok()) {
    LOG(WARNING) << "Unable to retrieve initial config: "
                 << status.getMessage();
  }

  for (const auto& gen_config_response : gen_config_response_list) {
    for (const auto& configuration_descriptor : gen_config_response) {
      const auto& config_file_path = configuration_descriptor.first;
      const auto& config_contents = configuration_descriptor.second;

      VLOG(1) << "Found configuration file: " << config_file_path;

      configuration_file_map.insert({config_file_path, config_contents});
    }
  }

  return osquery::Status::success();
}

osquery::Status createSubscriptionRequest(const BrokerRequestType& rType,
                                          const broker::bro::Event& event,
                                          const std::string& incoming_topic,
                                          SubscriptionRequest& sr) {
  // Check number of fields
  auto event_args = event.args();
  unsigned long numFields;
  if (rType == EXECUTE) {
    numFields = 5;
  } else if (rType == SUBSCRIBE || rType == UNSUBSCRIBE) {
    numFields = 6;
  } else {
    return osquery::Status::failure("Unknown Subscription Request Type '" +
                                    std::to_string(rType) + "'");
  }

  if (event_args.size() != numFields) {
    return osquery::Status::failure(
        std::to_string(event_args.size()) + " instead of " +
        std::to_string(numFields) + " fields in '" +
        kBrokerRequestTypeNames.at(rType) + "' message '" + event.name());
  }

  // Query String
  if (!broker::is<std::string>(event_args[1])) {
    return osquery::Status::failure("SQL query is not a string");
  }
  sr.query = broker::get<std::string>(event_args[1]);

  // Response Event Name
  if (!broker::is<std::string>(event_args[0])) {
    return osquery::Status::failure("Response Event Name is not a string");
  }
  sr.response_event = broker::get<std::string>(event_args[0]);

  // Cookie
  auto cookie = broker::to_string(event_args[2]);
  sr.cookie = cookie;

  // Response Topic
  if (!broker::is<std::string>(event_args[3])) {
    return osquery::Status::failure("Response Topic Name is not a string");
  }
  if (broker::get<std::string>(event_args[3]).empty()) {
    sr.response_topic = incoming_topic;
    LOG(WARNING) << "No response topic given for event '" << sr.response_event
                 << "' reporting back to "
                    "incoming topic '"
                 << incoming_topic << "'";
  } else {
    sr.response_topic = broker::get<std::string>(event_args[3]);
  }

  // Update Type
  std::string update_type = broker::to_string(event_args[4]);
  if (update_type == "ADDED") {
    sr.added = true;
    sr.removed = false;
    sr.snapshot = false;
  } else if (update_type == "REMOVED") {
    sr.added = false;
    sr.removed = true;
    sr.snapshot = false;
  } else if (update_type == "BOTH") {
    sr.added = true;
    sr.removed = true;
    sr.snapshot = false;
  } else if (update_type == "SNAPSHOT") {
    sr.added = false;
    sr.removed = false;
    sr.snapshot = true;
  } else {
    return osquery::Status::failure("Unknown update type");
  }

  // If one-time query
  if (rType == EXECUTE) {
    if (sr.added || sr.removed || !sr.snapshot) {
      LOG(WARNING) << "Only possible to query SNAPSHOT for one-time queries";
    }
    return osquery::Status::success();
  }
  // SUBSCRIBE or UNSUBSCRIBE
  if (sr.snapshot) {
    LOG(WARNING)
        << "Only possible to query ADD and/or REMOVE for scheduled queries";
  }

  // Interval
  if (!broker::is<uint64_t>(event_args[5])) {
    return osquery::Status::failure("Interval is not a number");
  }
  sr.interval = broker::get<uint64_t>(event_args[5]);

  return osquery::Status::success();
}

osquery::Status serializeDistributedQueryRequestsJSON(
    const std::vector<osquery::DistributedQueryRequest>& rs,
    std::string& json) {
  auto doc = osquery::JSON::newObject();
  auto queries_obj = doc.getObject();
  for (const auto r : rs) {
    doc.addCopy(r.id, r.query, queries_obj);
  }

  doc.add("queries", queries_obj);

  return doc.toString(json);
}

osquery::Status parseDistributedQueryResultsJSON(
    const std::string& json,
    std::vector<std::pair<std::string, std::pair<osquery::QueryData, int>>>&
        rs) {
  auto doc = osquery::JSON::newObject();
  auto s = doc.fromString(json);
  if (!s.ok()) {
    return s;
  }

  // Browse query results
  std::vector<std::string> qd_ids;
  std::vector<osquery::QueryData> qds;
  if (doc.doc().HasMember("queries")) {
    const auto& queries = doc.doc()["queries"];
    assert(queries.IsObject());

    if (queries.IsObject()) {
      for (const auto& query_entry : queries.GetObject()) {
        // Get Request ID
        if (!query_entry.name.IsString()) {
          return osquery::Status::failure(
              "Distributed query result name is not a string");
        }
        auto name = std::string(query_entry.name.GetString());
        if (name.empty()) {
          return osquery::Status::failure(
              "Distributed query result name is empty");
        }
        qd_ids.push_back(name);

        // Get Request Results
        if (!query_entry.value.IsArray()) {
          return osquery::Status::failure(
              "Distributed query result is not an array");
        }
        osquery::QueryData qd;
        osquery::deserializeQueryData(query_entry.value, qd);
        if (!s.ok()) {
          return s;
        }
        qds.push_back(qd);
      }
    }
  }

  // Browse query osquery::Statuses
  std::vector<std::string> st_ids;
  std::vector<int> sts;
  if (doc.doc().HasMember("statuses")) {
    const auto& statuses = doc.doc()["statuses"];
    assert(statuses.IsObject());

    if (statuses.IsObject()) {
      for (const auto& status_entry : statuses.GetObject()) {
        // Get Request ID
        if (!status_entry.name.IsString()) {
          return osquery::Status::failure(
              "Distributed query status name is not a string");
        }
        auto name = std::string(status_entry.name.GetString());
        if (name.empty()) {
          return osquery::Status::failure(
              "Distributed query status name is empty");
        }
        st_ids.push_back(name);

        // Get Query osquery::Status
        if (!status_entry.value.IsInt()) {
          return osquery::Status::failure(
              "Distributed query status is not an int");
        }
        auto code = status_entry.value.GetInt();
        sts.push_back(code);
      }
    }
  }

  assert(qd_ids.size() == st_ids.size());
  int idx = 0;
  for (const auto& name : qd_ids) {
    assert(qd_ids[idx] == st_ids[idx]);
    assert(name == qd_ids[idx]);

    rs.emplace_back(name, std::make_pair(qds.at(idx), sts.at(idx)));
    idx += 1;
  }

  return osquery::Status::success();
}

} // namespace zeek
