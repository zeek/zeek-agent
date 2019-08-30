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

#include <iostream>
#include <list>
#include <map>

#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/status.h>
#include <osquery/system.h>

#include <zeek-remote/types.h>

namespace zeek {
/**
 * @brief Manager class for queries that are received via broker.
 *
 * The QueryManager is a singleton to keep track of queries that are requested
 * via broker.
 */
class IQueryManager : private boost::noncopyable {
 public:
  using Ref = std::shared_ptr<IQueryManager>;
  static osquery::Status create(Ref& ref);

  virtual ~IQueryManager() = default;

  /**
   * @brief Reset the QueryManager to its initial state.
   *
   * This makes the BrokerManager to remove all schedule and one-time queries
   * from tracking
   */
  virtual osquery::Status reset() = 0;

  /**
   * @brief Add a one-time query to tracking
   *
   * @param qr the subscription request for this one-time query
   * @return the unique queryID assigned this query
   */
  virtual std::string addOneTimeQueryEntry(const SubscriptionRequest& qr) = 0;

  /**
   * @brief Add a schedule query to tracking
   *
   * @param qr the subscription request for this schedule query
   * @return
   */
  virtual osquery::Status addScheduleQueryEntry(
      const SubscriptionRequest& qr) = 0;

  /// Find the queryID for a query that is tracked given by the query string
  virtual std::string findIDForQuery(const std::string& query) = 0;

  /// Find the query string and the query type for a query that is tracked given
  /// by the queryID
  virtual osquery::Status findQueryAndType(const std::string& queryID,
                                           std::string& qtype,
                                           std::string& query) = 0;

  /// Remove a query from tracking given by the query string
  virtual osquery::Status removeQueryEntry(const std::string& query) = 0;

  /// Update the core schedule with the queries that are currently subscribed
  /// to from Zeek
  virtual osquery::Status updateSchedule() = 0;

  /// Get the cookie the was given in the subscription request of a query given
  /// by the queryID
  virtual std::string getEventCookie(const std::string& queryID) = 0;

  /// Get the response event name the was given in the subscription request of a
  /// query given by the queryID
  virtual std::string getEventName(const std::string& queryID) = 0;

  /// Get the response event topic the was given in the subscription request of
  /// a query given by the queryID
  virtual std::string getEventTopic(const std::string& queryID) = 0;
};
} // namespace zeek
