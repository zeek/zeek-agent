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
  virtual ~QueryManager() override;

  // IQueryManager interface
  virtual osquery::Status reset() override;

  virtual std::string addOneTimeQueryEntry(
      const SubscriptionRequest& qr) override;

  virtual osquery::Status addScheduleQueryEntry(
      const SubscriptionRequest& qr) override;

  virtual osquery::Status addQueryEntry(const std::string& queryID,
                                        const SubscriptionRequest& qr,
                                        const std::string& qtype) override;

  virtual std::string findIDForQuery(const std::string& query) override;

  virtual osquery::Status findQueryAndType(const std::string& queryID,
                                           std::string& qtype,
                                           std::string& query) override;

  virtual osquery::Status removeQueryEntry(const std::string& query) override;
  virtual osquery::Status purgeQuery(const std::string& query) override;
  virtual std::string getQueryConfigString() override;
  virtual osquery::Status updateSchedule() override;
  virtual std::string getEventCookie(const std::string& queryID) override;
  virtual std::string getEventName(const std::string& queryID) override;
  virtual std::string getEventTopic(const std::string& queryID) override;
  virtual std::vector<std::string> getQueryIDs() override;

 protected:
  QueryManager();

 private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  friend class IQueryManager;
};
} // namespace zeek
