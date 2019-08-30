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

#include <string>
#include <unordered_set>

#include <gtest/gtest.h>
#include <rapidjson/document.h>
#include <rocksdb/status.h>

namespace zeek {
class TestDatabaseInterface final : public IDatabaseInterface {
 public:
  mutable std::unordered_set<std::string> key_list;

  virtual ~TestDatabaseInterface() = default;

  virtual osquery::Status deleteKey(const std::string&,
                                    const std::string& key) const override {
    auto it = key_list.find(key);
    if (it == key_list.end()) {
      return osquery::Status::failure("Key not found");
    }

    key_list.erase(it);
    return osquery::Status::success();
  }
};

TEST(QueryManager, addQueryEntry) {
  const std::string kQueryId{"dummy_query_id"};
  const std::string kQueryString{"SELECT * FROM processes"};
  const std::string kResponseEvent{"response_event"};
  const std::string kResponseTopic{"response_topic"};
  const std::string kCookie{"cookie"};
  const std::uint64_t kInterval{10U};
  const bool kAdded{false};
  const bool kRemoved{false};
  const bool kSnapshot{false};

  // clang-format off
  SubscriptionRequest base_subscription_request = {
    kQueryString,
    kResponseEvent,
    kResponseTopic,
    kCookie,
    kInterval,
    kAdded,
    kRemoved,
    kSnapshot
  };
  // clang-format on

  {
    auto test_database_interface = new TestDatabaseInterface;

    // clang-format off
    test_database_interface->key_list = {
      // Query
      "query." + kQueryId,

      // Counter
      kQueryId + "counter",

      // Query data
      kQueryId,

      // Epoch
      kQueryId + "epoch"
    };
    // clang-format on

    std::shared_ptr<IDatabaseInterface> database_interface(
        test_database_interface);

    QueryManager::Context context;
    auto status = QueryManager::addQueryEntry(database_interface,
                                              context,
                                              kQueryId,
                                              base_subscription_request,
                                              "SCHEDULE");

    ASSERT_TRUE(status.ok());
    ASSERT_TRUE(test_database_interface->key_list.empty());

    ASSERT_EQ(context.schedule_queries.size(), 1U);
    ASSERT_TRUE(context.schedule_queries.find(kQueryId) !=
                context.schedule_queries.end());

    const auto& entry = context.schedule_queries.at(kQueryId);

    ASSERT_EQ(std::get<0>(entry), kQueryId);
    ASSERT_EQ(std::get<1>(entry), kQueryString);
    ASSERT_EQ(std::get<2>(entry), static_cast<std::uint64_t>(kInterval));
    ASSERT_EQ(std::get<3>(entry), kAdded);
    ASSERT_EQ(std::get<4>(entry), kRemoved);
    ASSERT_EQ(std::get<5>(entry), kSnapshot);
  }

  {
    auto database_interface = std::make_shared<TestDatabaseInterface>();

    QueryManager::Context context;
    auto status = QueryManager::addQueryEntry(database_interface,
                                              context,
                                              kQueryId,
                                              base_subscription_request,
                                              "ONETIME");

    ASSERT_TRUE(status.ok());
    ASSERT_EQ(context.one_time_queries.size(), 1U);
    ASSERT_TRUE(context.one_time_queries.find(kQueryId) !=
                context.one_time_queries.end());

    const auto& entry = context.one_time_queries.at(kQueryId);

    ASSERT_EQ(std::get<0>(entry), kQueryId);
    ASSERT_EQ(std::get<1>(entry), kQueryString);
  }

  {
    auto database_interface = std::make_shared<TestDatabaseInterface>();

    QueryManager::Context context;
    auto status = QueryManager::addQueryEntry(database_interface,
                                              context,
                                              kQueryId,
                                              base_subscription_request,
                                              "XXXXXX");

    ASSERT_FALSE(status.ok());
  }

  {
    auto database_interface = std::make_shared<TestDatabaseInterface>();

    QueryManager::Context context;
    context.schedule_queries[kQueryId] = {};

    auto status = QueryManager::addQueryEntry(database_interface,
                                              context,
                                              kQueryId,
                                              base_subscription_request,
                                              "SCHEDULE");

    ASSERT_FALSE(status.ok());
  }
}

TEST(QueryManager, purgeScheduledQueryFromDatabase) {
  auto test_database_interface = new TestDatabaseInterface;

  // clang-format off
  test_database_interface->key_list = {
    // Query
    "query.dummy",

    // Counter
    "dummycounter",

    // Query data
    "dummy",

    // Epoch
    "dummyepoch"
  };
  // clang-format on

  std::shared_ptr<IDatabaseInterface> database_interface(
      test_database_interface);

  QueryManager::purgeScheduledQueryFromDatabase(database_interface, "dummy");

  ASSERT_TRUE(test_database_interface->key_list.empty());
}

TEST(QueryManager, getQueryConfigString) {
  const std::string kQueryId{"dummy_query_id"};
  const std::string kQueryString{"SELECT * FROM processes"};
  const std::uint64_t kQueryInterval = 10U;
  const bool kQueryAdded{true};
  const bool kQueryRemoved{false};
  const bool kSnapshot{false};

  QueryManager::Context context;
  context.schedule_queries[kQueryId] = zeek::ScheduleQueryEntry{kQueryId,
                                                                kQueryString,
                                                                kQueryInterval,
                                                                kQueryAdded,
                                                                kQueryRemoved,
                                                                kSnapshot};

  auto config_string = QueryManager::getQueryConfigString(context);
  ASSERT_TRUE(!config_string.empty());

  rapidjson::Document document;
  document.Parse(config_string);
  ASSERT_FALSE(document.HasParseError());
  ASSERT_TRUE(document.IsObject());
  ASSERT_TRUE(document.HasMember("schedule"));

  const auto& schedule = document["schedule"];
  ASSERT_TRUE(schedule.IsObject());

  ASSERT_TRUE(schedule.HasMember(kQueryId));
  const auto& query_object = schedule[kQueryId];

  ASSERT_TRUE(query_object.HasMember("query"));
  const auto& query_string = query_object["query"];

  ASSERT_TRUE(query_string.IsString());
  ASSERT_EQ(query_string.GetString(), kQueryString + ";");

  ASSERT_TRUE(query_object.HasMember("interval"));
  const auto& query_interval = query_object["interval"];

  ASSERT_TRUE(query_interval.IsNumber());
  ASSERT_EQ(query_interval.GetInt(), kQueryInterval);

  ASSERT_TRUE(query_object.HasMember("added"));
  const auto& query_added = query_object["added"];

  ASSERT_TRUE(query_added.IsNumber());
  ASSERT_EQ(query_added.GetInt(), kQueryAdded ? 1 : 0);

  ASSERT_TRUE(query_object.HasMember("removed"));
  const auto& query_removed = query_object["removed"];

  ASSERT_TRUE(query_removed.IsNumber());
  ASSERT_EQ(query_removed.GetInt(), kQueryRemoved ? 1 : 0);

  ASSERT_TRUE(query_object.HasMember("snapshot"));
  const auto& snapshot = query_object["snapshot"];

  ASSERT_TRUE(snapshot.IsNumber());
  ASSERT_EQ(snapshot.GetInt(), kSnapshot ? 1 : 0);
}

TEST(QueryManager, getQueryIDs) {
  QueryManager::Context context;
  std::vector<std::string> expected_query_id_list;

  for (auto i = 0U; i < 10U; ++i) {
    auto query_id = "schedule_queries_" + std::to_string(i);
    context.schedule_queries.insert({query_id, {}});
    expected_query_id_list.push_back(query_id);

    query_id = "one_time_queries_" + std::to_string(i);
    context.one_time_queries.insert({query_id, {}});
    expected_query_id_list.push_back(query_id);
  }

  auto query_id_list = QueryManager::getQueryIDs(context);
  ASSERT_EQ(query_id_list.size(), expected_query_id_list.size());

  for (const auto& expected_query_id : expected_query_id_list) {
    auto it = std::find(
        query_id_list.begin(), query_id_list.end(), expected_query_id);

    ASSERT_TRUE(it != query_id_list.end());
  }
}

TEST(QueryManager, findIDForQuery) {
  const std::string kQueryId01{"01"};
  const std::string kQueryString01{"SELECT * FROM processes;"};

  const std::string kQueryId02{"02"};
  const std::string kQueryString02{"SELECT * FROM users;"};

  QueryManager::Context context;
  context.schedule_queries.insert(
      {kQueryId01, {kQueryId01, kQueryString01, 10, true, false, false}});

  context.one_time_queries.insert({kQueryId02, {kQueryId02, kQueryString02}});

  auto id = QueryManager::findIDForQuery(context, kQueryString01);
  EXPECT_EQ(id, kQueryId01);

  id = QueryManager::findIDForQuery(context, kQueryString02);
  EXPECT_EQ(id, kQueryId02);
}

TEST(QueryManager, removeQueryEntry) {
  const std::string kQueryId{"01"};
  const std::string kQueryString{"SELECT * FROM processes;"};

  auto test_database_interface = new TestDatabaseInterface;

  // clang-format off
  test_database_interface->key_list = {
    // Query
    "query." + kQueryId,

    // Counter
    kQueryId + "counter",

    // Query data
    kQueryId,

    // Epoch
    kQueryId + "epoch"
  };
  // clang-format on

  std::shared_ptr<IDatabaseInterface> database_interface(
      test_database_interface);

  QueryManager::Context context;

  context.schedule_queries.insert(
      {kQueryId, {kQueryId, kQueryString, 10, true, false, false}});

  auto status =
      QueryManager::removeQueryEntry(database_interface, context, kQueryString);

  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(test_database_interface->key_list.empty());
  ASSERT_TRUE(context.schedule_queries.empty());

  context.one_time_queries.insert({kQueryId, {kQueryId, kQueryString}});
  status =
      QueryManager::removeQueryEntry(database_interface, context, kQueryString);

  ASSERT_TRUE(status.ok());
  ASSERT_TRUE(context.one_time_queries.empty());

  status = QueryManager::removeQueryEntry(
      database_interface, context, "Dummy string");

  ASSERT_FALSE(status.ok());
}
} // namespace zeek
