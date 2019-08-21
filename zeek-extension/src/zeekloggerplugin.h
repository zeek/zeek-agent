/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/sdk.h>

namespace zeek {
class ZeekLoggerPlugin : public osquery::LoggerPlugin {
 public:
  osquery::Status setUp() override;

  virtual osquery::Status logString(const std::string& s) override;

  virtual osquery::Status logSnapshot(const std::string& s) override;

  virtual osquery::Status logStatus(
      const std::vector<osquery::StatusLogLine>& log) override;

  virtual void init(const std::string& name,
                    const std::vector<osquery::StatusLogLine>& log) override;
};
} // namespace zeek
