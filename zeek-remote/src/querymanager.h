/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include "idatabaseinterface.h"

#include <zeek-remote/iquerymanager.h>

namespace zeek {
/**
 * @brief Manager class for queries that are received via broker.
 *
 * The QueryManager is a singleton to keep track of queries that are requested
 * via broker.
 */
class QueryManager final : public IQueryManager {
 public:
  struct Context final {
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

  virtual ~QueryManager() override;

  // IQueryManager interface
  virtual osquery::Status reset() override;

  virtual std::string addOneTimeQueryEntry(
      const SubscriptionRequest& qr) override;

  virtual osquery::Status addScheduleQueryEntry(
      const SubscriptionRequest& qr) override;

  virtual osquery::Status findQueryAndType(const std::string& queryID,
                                           std::string& qtype,
                                           std::string& query) override;

  virtual osquery::Status removeQueryEntry(const std::string& query) override;
  virtual osquery::Status updateSchedule() override;
  virtual std::string getEventCookie(const std::string& queryID) override;
  virtual std::string getEventName(const std::string& queryID) override;
  virtual std::string getEventTopic(const std::string& queryID) override;

 protected:
  QueryManager(DatabaseInterfaceRef database_interface);

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  std::string generateQueryId();

 public:
  /**
   * @brief Add a query to tracking with fixed properties
   *
   * @param queryID the queryID to use for this query
   * @param qr the subscription request for this query
   * @param qtype the type of the query ("SCHEDULE" or "ONETIME")
   * @return
   */

  static osquery::Status addQueryEntry(DatabaseInterfaceRef database_interface,
                                       Context& context,
                                       const std::string& query_id,
                                       const SubscriptionRequest& qr,
                                       const std::string& qtype);

  /// Remove all references to the query from the database
  static void purgeScheduledQueryFromDatabase(
      DatabaseInterfaceRef database_interface, const std::string& query_id);

  /// Generate configuration data for the query schedule (osqueryd) from the
  /// broker query tracking
  static std::string getQueryConfigString(const Context& context);

  /// Get a vector of all currently tracked queryIDs
  static std::vector<std::string> getQueryIDs(const Context& context);

  static std::string findIDForQuery(const Context& context,
                                    const std::string& query);

  static osquery::Status removeQueryEntry(
      DatabaseInterfaceRef database_interface,
      Context& context,
      const std::string& query);

  static osquery::Status findQueryAndType(const Context& context,
                                          const std::string& queryID,
                                          std::string& qtype,
                                          std::string& query);

  friend class IQueryManager;
};
} // namespace zeek
