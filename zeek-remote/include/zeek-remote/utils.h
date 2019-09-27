/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <broker/bro.hh>
#include <broker/broker.hh>
#include <broker/endpoint.hh>

#include <osquery/distributed.h>
#include <osquery/status.h>
#include <osquery/system.h>

#include <map>

#include <zeek-remote/types.h>

namespace zeek {
using ConfigurationFileMap = std::map<std::string, std::string>;

osquery::Status getOsqueryConfiguration(
    ConfigurationFileMap& configuration_file_map);

/**
 * @brief Parse an incoming broker message as subscription request.
 *
 * Incoming broker messages can contain SQL queries to be executed by osquery
 * hosts. There are two kind of queries: Ad-hoc (one-time) or Schedule
 * (repeating). Requests for both kinds can be described as SubscriptionRequest.
 *
 * @param rType the request type (EXECUTE, SUBSCRIBE or UNSUBSCRIBE)
 * @param event the incoming broker message that is parsed
 * @param incoming_topic the broker topic where the message was received on
 * @param sr the SubscriptionRequest to be filled
 * @return
 */
osquery::Status createSubscriptionRequest(const BrokerRequestType& rType,
                                          const broker::bro::Event& event,
                                          const std::string& incoming_topic,
                                          SubscriptionRequest& sr);

/**
 * @brief Serialize a vector of DistributedQueryRequest objects into a JSON
 * string
 *
 * @param rs the vector of DistributedQueryRequests to serialize
 * @param json the output JSON string
 *
 * @return osquery::Status indicating the success or failure of the operation
 */
osquery::Status serializeDistributedQueryRequestsJSON(
    const std::vector<osquery::DistributedQueryRequest>& rs, std::string& json);
/**
 * @brief Parses a serialized DistributedQueryResult
 *
 * @param json the serialized json string of the DistributedQueryResult
 * @param rs the output vector with QueryData and osquery::StatusCode per
 * requestID
 * @return osquery::Status indicating the success or failure of the operation
 */
osquery::Status parseDistributedQueryResultsJSON(
    const std::string& json,
    std::vector<std::pair<std::string, std::pair<osquery::QueryData, int>>>&
        rs);
} // namespace zeek
