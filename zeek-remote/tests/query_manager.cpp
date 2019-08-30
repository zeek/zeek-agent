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
} // namespace zeek
