/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/sdk.h>

#include <zeek-remote/utils.h>

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
