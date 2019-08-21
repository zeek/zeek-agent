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

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

#include <osquery/distributed.h>
#include <osquery/status.h>
#include <osquery/system.h>

namespace zeek {
struct BrokerTopics final {
  static const std::string ALL;
  static const std::string ANNOUNCE;
  static const std::string PRE_INDIVIDUALS;
  static const std::string PRE_GROUPS;
  static const std::string PRE_CUSTOMS;
};

struct BrokerEvents final {
  static const std::string HOST_NEW;
  static const std::string HOST_JOIN;
  static const std::string HOST_LEAVE;
  static const std::string HOST_EXECUTE;
  static const std::string HOST_SUBSCRIBE;
  static const std::string HOST_UNSUBSCRIBE;
};

/**
 * @brief Request types for query subscriptions
 */
enum BrokerRequestType { EXECUTE = 0, SUBSCRIBE = 1, UNSUBSCRIBE = 2 };

/**
 * @brief Names of the subscription request types
 */
const std::map<BrokerRequestType, std::string> kBrokerRequestTypeNames = {
    {EXECUTE, "EXECUTE"},
    {SUBSCRIBE, "SUBSCRIBE"},
    {UNSUBSCRIBE, "UNSUBSCRIBE"},
};

/**
 * @brief Internal definition of a query for scheduling
 *
 * The fields correspond to ID, query, interval, added, removed, snapshot. This
 * representation is used to keep track of active schedule subscriptions.
 */
typedef std::tuple<std::string, std::string, int, bool, bool, bool>
    ScheduleQueryEntry;

/**
 * @brief Internal definition of a query for one-time execution
 *
 * The fields correspond to ID, query. This representation is used to keep track
 * of active one-time query executions.
 */
typedef std::tuple<std::string, std::string> OneTimeQueryEntry;

/**
 * @brief Internal definition of a subscription request
 *
 * A subscription request is a common data structure to describe the incoming
 * query request and to hold its parameters. This definition is valid for all
 * request types in BrokerRequestType.
 */
struct SubscriptionRequest {
  std::string query; // The requested SQL query
  std::string response_event; // The event name for the response event
  std::string response_topic; // The topic name for the response event
  std::string cookie = "";
  uint64_t interval = 10;
  bool added = true;
  bool removed = false;
  bool snapshot = false;
};
} // namespace zeek
