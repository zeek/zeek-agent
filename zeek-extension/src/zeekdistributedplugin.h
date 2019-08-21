/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/distributed.h>

namespace zeek {
/**
 * @brief Distributed Plugin for the communication with Bro via broker
 *
 * This DistributedPlugin is the main entry point for the communication with
 * Bro. It implements a server-"loop" to wait for any incoming messages via
 * broker. It utilizes the BrokerManager and QueryManager to keep state about
 * broker connections and query requests, respectively.
 *
 */
class ZeekDistributedPlugin final : public osquery::DistributedPlugin {
 public:
  /**
   * @brief Setup of the plugin and preparation of the BrokerManager
   *
   * Initialization of the BrokerManager by connecting to the remote broker
   * endpoint, joining predefined groups and subscribing to predefined topics,
   * and announcing this osquery host.
   *
   * @return
   */
  virtual osquery::Status setUp() override;

  /**
   * @brief Implementation of the main server-"loop" to process incoming
   * messages
   *
   * This base method was originally designed to retrieve the latest remote
   * configuration from server. However, the communication pattern with Bro is
   * not request-response-based but event-based. Thus, this method
   * implementation blocks until the next broker message is available to be
   * read. After return, this method is meant to be immediately be called again
   * to wait and process the next message.
   *
   * This method can be thought of the main-loop for receiving messages.
   * Incoming messages are parsed and the respective functions are called. There
   * are mainly three actions available:
   *   1) Schedule Subscription: registers a new query that is pushed to the
   * osqueryd daemon for query schedule
   *   2) Schedule Unsibscription: unregister a previously subscribed schedule
   * query and remove it from osquery daemon
   *   3) One-Time Execution: make the parent execute an one-time query
   *
   * @param json the one-time queries to be executed by the "parent"
   * @return
   */
  virtual osquery::Status getQueries(std::string& json) override;

  /**
   * @brief Write the results of the one-time queries via the bro logger plugin
   *
   * @param json the results of the one-time queries
   * @return
   */
  virtual osquery::Status writeResults(const std::string& json) override;
};
} // namespace zeek
