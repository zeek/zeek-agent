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
} // namespace zeek
