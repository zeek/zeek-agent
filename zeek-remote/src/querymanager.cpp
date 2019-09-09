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
namespace {
class OsqueryDatabaseInterface final : public IDatabaseInterface {
 public:
  virtual ~OsqueryDatabaseInterface() = default;

  virtual osquery::Status deleteKey(const std::string& domain,
                                    const std::string& key) const override {
    osquery::deleteDatabaseValue(domain, key);
  }
};
} // namespace

struct QueryManager::PrivateData final {
  // Holds instance data
  Context context;

  // Interface used to read, delete and write keys into the
  // database
  DatabaseInterfaceRef database_interface;

  // Next unique QueryID
  int nextUID{1};
};

QueryManager::QueryManager(DatabaseInterfaceRef database_interface)
    : d(new PrivateData) {
  d->database_interface = database_interface;
}

QueryManager::~QueryManager() {}

osquery::Status QueryManager::reset() {
  auto query_id_list = getQueryIDs(d->context);

  for (const auto& query_id : query_id_list) {
    std::string query_type;
    std::string query_string;

    findQueryAndType(query_id, query_type, query_string);
    removeQueryEntry(query_string);
  }

  return osquery::Status::success();
}

std::string QueryManager::addOneTimeQueryEntry(const SubscriptionRequest& qr) {
  auto query_id = generateQueryId();

  auto status =
      addQueryEntry(d->database_interface, d->context, query_id, qr, "ONETIME");

  if (!status.ok()) {
    LOG(WARNING) << status.getMessage();
    return "";
  }

  return query_id;
}

osquery::Status QueryManager::addScheduleQueryEntry(
    const SubscriptionRequest& qr) {
  auto query_id = generateQueryId();

  return addQueryEntry(
      d->database_interface, d->context, query_id, qr, "SCHEDULE");
}

osquery::Status QueryManager::findQueryAndType(const std::string& queryID,
                                               std::string& qtype,
                                               std::string& query) {
  return findQueryAndType(d->context, queryID, qtype, query);
}

osquery::Status QueryManager::removeQueryEntry(const std::string& query) {
  return removeQueryEntry(d->database_interface, d->context, query);
}

osquery::Status QueryManager::updateSchedule() {
  std::map<std::string, std::string> new_config_schedule;

  VLOG(1) << "Applying new schedule based on Zeek queries";

  ConfigurationFileMap osquery_configuration;
  auto status = getOsqueryConfiguration(osquery_configuration);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to acquire the base configuration: "
               << status.getMessage();
  }

  osquery_configuration["/memory/zeek_distributed.conf"] =
      getQueryConfigString(d->context);

  osquery::Config::get().update(osquery_configuration);

  return osquery::Status::success();
}

std::string QueryManager::getEventCookie(const std::string& queryID) {
  return d->context.event_cookies.at(queryID);
}

std::string QueryManager::getEventName(const std::string& queryID) {
  return d->context.event_names.at(queryID);
}

std::string QueryManager::getEventTopic(const std::string& queryID) {
  return d->context.event_topics.at(queryID);
}

std::string QueryManager::generateQueryId() {
  return "zeek_" + std::to_string(d->nextUID++);
}

osquery::Status QueryManager::addQueryEntry(
    DatabaseInterfaceRef database_interface,
    QueryManager::Context& context,
    const std::string& query_id,
    const SubscriptionRequest& qr,
    const std::string& qtype) {
  if (context.schedule_queries.count(query_id) > 0 or
      context.one_time_queries.count(query_id) > 0) {
    return osquery::Status::failure("QueryID '" + query_id +
                                    "' already exists");
  }

  if (qtype == "SCHEDULE") {
    purgeScheduledQueryFromDatabase(database_interface, query_id);

    context.schedule_queries[query_id] = ScheduleQueryEntry{
        query_id, qr.query, qr.interval, qr.added, qr.removed, qr.snapshot};

  } else if (qtype == "ONETIME") {
    context.one_time_queries[query_id] = OneTimeQueryEntry{query_id, qr.query};

  } else {
    return osquery::Status::failure("Unknown query type '" + qtype + "'");
  }

  context.event_cookies[query_id] = qr.cookie;
  context.event_names[query_id] = qr.response_event;
  context.event_topics[query_id] = qr.response_topic;

  return osquery::Status::success();
}

void QueryManager::purgeScheduledQueryFromDatabase(
    DatabaseInterfaceRef database_interface, const std::string& query_id) {
  // clang-format off
  std::vector<std::string> key_name_list = {
    // Query
    "query." + query_id,

    // Counter
    query_id + "counter",

    // Query data
    query_id,

    // Epoch
    query_id + "epoch"
  };
  // clang-format on

  for (const auto& key_name : key_name_list) {
    auto status = database_interface->deleteKey(osquery::kQueries, key_name);
    if (!status.ok()) {
      VLOG(1) << "Failed to erase the following database key: " << key_name
              << " (" << status.getMessage() << ")";
    }
  }
}

std::string QueryManager::getQueryConfigString(const Context& context) {
  // Format each query
  std::vector<std::string> schedule_queue;

  for (const auto& bq : context.schedule_queries) {
    auto i = bq.second;

    std::stringstream ss;
    ss << "\"" << std::get<0>(i) << "\": {\"query\": \"" << std::get<1>(i)
       << ";\", \"interval\": " << std::get<2>(i)
       << ", \"added\": " << std::get<3>(i)
       << ", \"removed\": " << std::get<4>(i)
       << ", \"snapshot\": " << std::get<5>(i) << "}";

    std::string query = ss.str();
    schedule_queue.push_back(query);
  }

  // Assemble queries
  std::stringstream ss;
  for (auto i = 0U; i < schedule_queue.size(); ++i) {
    if (i != 0) {
      ss << ",";
    }

    ss << schedule_queue.at(i);
  }

  const auto& queries = ss.str();

  std::string config =
      std::string("{\"schedule\": {") + queries + std::string("} }");

  return config;
}

std::vector<std::string> QueryManager::getQueryIDs(const Context& context) {
  std::vector<std::string> query_id_list;
  for (const auto& id : context.schedule_queries) {
    query_id_list.push_back(id.first);
  }

  for (const auto& id : context.one_time_queries) {
    query_id_list.push_back(id.first);
  }

  return query_id_list;
}

std::string QueryManager::findIDForQuery(const Context& context,
                                         const std::string& query) {
  for (const auto& e : context.schedule_queries) {
    const auto& queryID = e.first;
    const ScheduleQueryEntry& bqe = e.second;

    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }

  for (const auto& e : context.one_time_queries) {
    const auto& queryID = e.first;
    const OneTimeQueryEntry& bqe = e.second;

    if (std::get<1>(bqe) == query) {
      return queryID;
    }
  }

  return "";
}

osquery::Status QueryManager::removeQueryEntry(
    DatabaseInterfaceRef database_interface,
    Context& context,
    const std::string& query) {
  const auto& queryID = findIDForQuery(context, query);
  if (queryID == "") {
    return osquery::Status::failure("Unable to find ID for query '" + query +
                                    "'");
  }

  // Delete query info
  context.event_cookies.erase(queryID);
  context.event_topics.erase(queryID);
  context.event_names.erase(queryID);

  if (context.schedule_queries.count(queryID) >= 1) {
    VLOG(1) << "Deleting schedule query '" << query << "' with queryID '"
            << queryID << "'";

    context.schedule_queries.erase(queryID);
  }

  if (context.one_time_queries.count(queryID) >= 1) {
    VLOG(1) << "Deleting onetime query '" << query << "' with queryID '"
            << queryID << "'";

    context.one_time_queries.erase(queryID);
  }

  // Purge from database
  // TODO: scheduled queries only?
  purgeScheduledQueryFromDatabase(database_interface, queryID);

  return osquery::Status::success();
}

osquery::Status QueryManager::findQueryAndType(const Context& context,
                                               const std::string& query_id,
                                               std::string& query_type,
                                               std::string& query_string) {
  query_type = {};
  query_string = {};

  if (context.schedule_queries.count(query_id) > 0) {
    query_type = "SCHEDULE";
    query_string = std::get<1>(context.schedule_queries.at(query_id));

  } else if (context.one_time_queries.count(query_id) > 0) {
    query_type = "ONETIME";
    query_string = std::get<1>(context.one_time_queries.at(query_id));

  } else {
    return osquery::Status::failure("QueryID '" + query_id +
                                    "' not in brokerQueries");
  }

  return osquery::Status::success();
}

osquery::Status IQueryManager::create(Ref& ref) {
  try {
    ref.reset();

    std::shared_ptr<IDatabaseInterface> database_interface(
        new OsqueryDatabaseInterface);

    auto ptr = new QueryManager(database_interface);

    ref.reset(ptr);
    return osquery::Status::success();

  } catch (const std::bad_alloc&) {
    return osquery::Status::failure("Failed to create the QueryManager object");

  } catch (const osquery::Status& status) {
    return status;
  }
}
} // namespace zeek
