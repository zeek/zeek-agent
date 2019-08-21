/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <zeek-remote/types.h>

namespace zeek {
#define ZEEK_TOPIC_PREFIX "/bro/osquery/"

const std::string BrokerTopics::ALL{ZEEK_TOPIC_PREFIX "hosts"};
const std::string BrokerTopics::ANNOUNCE{ZEEK_TOPIC_PREFIX "host_announce"};
const std::string BrokerTopics::PRE_INDIVIDUALS{ZEEK_TOPIC_PREFIX "host/"};
const std::string BrokerTopics::PRE_GROUPS{ZEEK_TOPIC_PREFIX "group/"};
const std::string BrokerTopics::PRE_CUSTOMS{ZEEK_TOPIC_PREFIX "custom/"};

const std::string BrokerEvents::HOST_NEW{"osquery::host_new"};
const std::string BrokerEvents::HOST_JOIN{"osquery::host_join"};
const std::string BrokerEvents::HOST_LEAVE{"osquery::host_leave"};
const std::string BrokerEvents::HOST_EXECUTE{"osquery::host_execute"};
const std::string BrokerEvents::HOST_SUBSCRIBE{"osquery::host_subscribe"};
const std::string BrokerEvents::HOST_UNSUBSCRIBE{"osquery::host_unsubscribe"};
} // namespace zeek
