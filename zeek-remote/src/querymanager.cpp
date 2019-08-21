/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "querymanager.h"

#include <iostream>
#include <list>
#include <sstream>

#include <osquery/config.h>
#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include <zeek-remote/utils.h>

namespace zeek {
struct QueryManager::PrivateData final {
  // Next unique QueryID
  int nextUID{1};

  // Collection of SQL Schedule Subscription queries, Key: QueryID
  std::map<std::string, ScheduleQueryEntry> schedule_queries;

  // Collection of SQL One-Time Subscription queries, Key: QueryID
  std::map<std::string, OneTimeQueryEntry> one_time_queries;

  // Some mapping to maintain the SQL subscriptions
  //  Key: QueryID, Value: Event Cookie to use for the response
  std::map<std::string, std::string> event_cookies;

  //  Key: QueryID, Value: Event Name to use for the response
  std::map<std::string, std::string> event_names;

  //  Key: QueryID, Value: Topic to use for the response
  std::map<std::string, std::string> event_topics;
};

QueryManager::QueryManager() : d(new PrivateData) {}

QueryManager::~QueryManager() {}

osquery::Status QueryManager::reset() {
  std::vector<std::string> queryIDs = getQueryIDs();

  // Collect query strings
  std::vector<std::string> queries;
  for (const auto& id : d->schedule_queries) {
    queries.push_back(std::get<1>(id.second));
  }

  for (const auto& id : d->one_time_queries) {
    queries.push_back(std::get<1>(id.second));
  }

  for (const auto& queryID : queryIDs) {
    std::string query;
    std::string qType;
    findQueryAndType(queryID, qType, query);
    removeQueryEntry(query);
  }

  return osquery::Status::success();
}

std::string QueryManager::addOneTimeQueryEntry(const SubscriptionRequest& qr) {
  const auto queryID = "bro_" + std::to_string(d->nextUID++);
  auto status = addQueryEntry(queryID, qr, "ONETIME");
  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return "";
  }
  return queryID;
}

osquery::Status QueryManager::addScheduleQueryEntry(
    const SubscriptionRequest& qr) {
  const auto queryID = "bro_" + std::to_string(d->nextUID++);
  return addQueryEntry(queryID, qr, "SCHEDULE");
}

osquery::Status QueryManager::addQueryEntry(const std::string& queryID,
                                            const SubscriptionRequest& qr,
                                            const std::string& qtype) {
  const auto& query = qr.query;
  const auto& cookie = qr.cookie;
  const auto& response_event = qr.response_event;
  const auto& response_topic = qr.response_topic;
  const int& interval = qr.interval;
  const bool& added = qr.added;
  const bool& removed = qr.removed;
  const bool& snapshot = qr.snapshot;
  if (d->schedule_queries.count(queryID) > 0 or
      d->one_time_queries.count(queryID) > 0) {
    return osquery::Status::failure("QueryID '" + queryID + "' already exists");
  }

  if (qtype == "SCHEDULE") {
    // Ensure no database artifacts
    purgeQuery(queryID);
    d->schedule_queries[queryID] =
        ScheduleQueryEntry{queryID, query, interval, added, removed, snapshot};
  } else if (qtype == "ONETIME") {
    d->one_time_queries[queryID] = OneTimeQueryEntry{queryID, query};
  } else {
    return osquery::Status::failure("Unknown query type '" + qtype + "'");
  }

  d->event_cookies[queryID] = cookie;
  d->event_names[queryID] = response_event;
  d->event_topics[queryID] = response_topic;
  return osquery::Status::success();
}

std::string QueryManager::findIDForQuery(const std::string& query) {
  // Search the queryID for this specific query
  for (const auto& e : d->schedule_queries) {
    const auto& queryID = e.first;
    const ScheduleQueryEntry& bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }

  for (const auto& e : d->one_time_queries) {
    const auto& queryID = e.first;
    const OneTimeQueryEntry& bqe = e.second;
    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }
  return "";
}

osquery::Status QueryManager::findQueryAndType(const std::string& queryID,
                                               std::string& qtype,
                                               std::string& query) {
  if (d->schedule_queries.count(queryID) > 0) {
    qtype = "SCHEDULE";
    query = std::get<1>(d->schedule_queries.at(queryID));
  } else if (d->one_time_queries.count(queryID) > 0) {
    qtype = "ONETIME";
    query = std::get<1>(d->one_time_queries.at(queryID));
  } else {
    return osquery::Status::failure("QueryID '" + queryID +
                                    "' not in brokerQueries");
  }
  return osquery::Status::success();
}

osquery::Status QueryManager::removeQueryEntry(const std::string& query) {
  const auto& queryID = findIDForQuery(query);
  if (queryID == "") {
    return osquery::Status::failure("Unable to find ID for query '" + query +
                                    "'");
  }

  // Delete query info
  d->event_cookies.erase(queryID);
  d->event_topics.erase(queryID);
  d->event_names.erase(queryID);
  if (d->schedule_queries.count(queryID) >= 1) {
    VLOG(1) << "Deleting schedule query '" << query << "' with queryID '"
            << queryID << "'";
    d->schedule_queries.erase(queryID);
  }
  if (d->one_time_queries.count(queryID) >= 1) {
    VLOG(1) << "Deleting onetime query '" << query << "' with queryID '"
            << queryID << "'";
    d->one_time_queries.erase(queryID);
  }

  // Purge from database
  // TODO: scheduled queries only?
  purgeQuery(queryID);

  return osquery::Status::success();
}

osquery::Status QueryManager::purgeQuery(const std::string& queryID) {
  // Delete Query
  auto status =
      osquery::deleteDatabaseValue(osquery::kQueries, "query." + queryID);

  // Delete Counter
  status = osquery::deleteDatabaseValue(osquery::kQueries, queryID + "counter");

  // Delete Query Data
  status = osquery::deleteDatabaseValue(osquery::kQueries, queryID);

  // Delete Epoch
  status = osquery::deleteDatabaseValue(osquery::kQueries, queryID + "epoch");

  return status;
}

std::string QueryManager::getQueryConfigString() {
  // Format each query
  std::vector<std::string> scheduleQ;
  for (const auto& bq : d->schedule_queries) {
    auto i = bq.second;
    std::stringstream ss;
    ss << "\"" << std::get<0>(i) << "\": {\"query\": \"" << std::get<1>(i)
       << ";\", \"interval\": " << std::get<2>(i)
       << ", \"added\": " << std::get<3>(i)
       << ", \"removed\": " << std::get<4>(i)
       << ", \"snapshot\": " << std::get<5>(i) << "}";
    std::string q = ss.str();
    scheduleQ.push_back(q);
  }

  // Assemble queries
  std::stringstream ss;
  for (size_t i = 0; i < scheduleQ.size(); ++i) {
    if (i != 0)
      ss << ",";
    ss << scheduleQ[i];
  }
  const auto& queries = ss.str();
  std::string config =
      std::string("{\"schedule\": {") + queries + std::string("} }");

  return config;
}

osquery::Status QueryManager::updateSchedule() {
  std::map<std::string, std::string> new_config_schedule;

  VLOG(1) << "Applying new schedule based on bro queries";

  ConfigurationFileMap osquery_configuration;
  auto status = getOsqueryConfiguration(osquery_configuration);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to acquire the base configuration: "
               << status.getMessage();
  }

  osquery_configuration["/memory/zeek_distributed.conf"] =
      getQueryConfigString();

  osquery::Config::get().update(osquery_configuration);

  return osquery::Status::success();
}

std::string QueryManager::getEventCookie(const std::string& queryID) {
  return d->event_cookies.at(queryID);
}

std::string QueryManager::getEventName(const std::string& queryID) {
  return d->event_names.at(queryID);
}

std::string QueryManager::getEventTopic(const std::string& queryID) {
  return d->event_topics.at(queryID);
}

std::vector<std::string> QueryManager::getQueryIDs() {
  // Collect queryIDs
  std::vector<std::string> queryIDs;
  for (const auto& id : d->schedule_queries) {
    queryIDs.push_back(id.first);
  }
  for (const auto& id : d->one_time_queries) {
    queryIDs.push_back(id.first);
  }

  return queryIDs;
}

osquery::Status IQueryManager::create(Ref& ref) {
  try {
    ref.reset();

    auto ptr = new QueryManager();
    ref.reset(ptr);

    return osquery::Status::success();

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Failed to create the QueryManager object");

  } catch (const osquery::Status& status) {
    return status;
  }
}
} // namespace zeek
