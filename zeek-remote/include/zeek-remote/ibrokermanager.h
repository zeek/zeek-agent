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

#include <memory>
#include <string>
#include <vector>

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

#include <osquery/query.h>
#include <osquery/status.h>

#include <zeek-remote/iquerymanager.h>
#include <zeek-remote/types.h>

namespace zeek {
using BrokerSubscriberRef = std::shared_ptr<broker::subscriber>;

/**
 * @brief Manager class for connections of the broker communication library.
 *
 * The BrokerManager is a singleton to keep track of broker communications and
 * to communicate via the broker endpoint. It provides various ways to retrieve
 * and modify connections. Each 'connection' is technically a subscription to a
 * topic in the publish-subscribe communication.
 *
 * One message_queue (i.e. message inbox) is created for each subscribed topic.
 * Among some predefined topics, joining a group results in subscribing the
 * corresponding topic to receive messages addressed for this group.
 */
class IBrokerManager {
 public:
  using Ref = std::unique_ptr<IBrokerManager>;
  static osquery::Status create(
      Ref& ref,
      const std::string& server_address,
      std::uint16_t server_port,
      const std::vector<std::string>& server_group_list,
      IQueryManager::Ref query_manager);

  virtual ~IBrokerManager() = default;

  /**
   * @brief Reset the BrokerManager to its initial state.
   *
   * This makes the BrokerManager to remove all groups and therefore unsubscribe
   * from all respective broker topics.
   *
   * @param groups_only Should one unsubscribe from groups only or additionally
   * also from predefined topics
   * @return
   */
  virtual osquery::Status reset(bool groups_only = true) = 0;

  /**
   * @brief Make the osquery host to join a group.
   *
   * Joining a group results in subscribing to the broker topic identified by
   * 'TOPIC_PRE_GROUPS + group'
   *
   * @param group the name of the group to join
   * @return
   */
  virtual osquery::Status addGroup(const std::string& group) = 0;

  /**
   * @brief Make the osquery host to leave a group.
   *
   * Leaving a group results in unsubscribing from the broker topic identified
   * by 'TOPIC_PRE_GROUPS + group'
   *
   * @param group the name of the group to leave
   * @return
   */
  virtual osquery::Status removeGroup(const std::string& group) = 0;

  /// Get the groups that the osquery host has joined
  virtual std::vector<std::string> getGroups() = 0;

  /// Subscribe to the topic
  virtual osquery::Status createSubscriber(const std::string& topic) = 0;

  /// Unsubscribe from the topic
  virtual osquery::Status deleteSubscriber(const std::string& topic) = 0;

  /// Get the message_queue (i.e. subscription message inbox) of the topic
  virtual osquery::Status getSubscriber(BrokerSubscriberRef& ref,
                                        const std::string& topic) = 0;

  /// Get all subscribed topics
  virtual std::vector<std::string> getTopics() = 0;

  /**
   * @brief checks for a working broker connection and wait if requested
   *
   * This is also used to initially establishing the connection and to reconnect
   * after failure
   *
   * @param timeout duration to wait before the peering attempt times out.
   * @return if connection is established
   */
  virtual osquery::Status checkConnection(long timeout = -1) = 0;

  /**
   * @brief Make the osquery host to announce itself to the remote broker
   * endpoint.
   *
   * This broker message includes the hosts nodeID, groups and network
   * interfaces
   *
   * @return
   */
  virtual osquery::Status announce() = 0;

  /// Get the file descriptor for peering to detection changes of connection
  /// osquery::Status
  virtual int getOutgoingConnectionFD() = 0;

  /// Send each entry in the QueryLogItem as broker event
  virtual osquery::Status logQueryLogItemToZeek(
      const osquery::QueryLogItem& qli) = 0;

  /// Send the broker message to a specific topic
  virtual osquery::Status sendEvent(const std::string& topic,
                                    const broker::bro::Event& msg) = 0;
};
} // namespace zeek
