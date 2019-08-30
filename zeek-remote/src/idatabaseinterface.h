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

#include <osquery/database.h>

namespace zeek {
class IDatabaseInterface {
 public:
  virtual ~IDatabaseInterface() = default;

  virtual osquery::Status deleteKey(const std::string& domain,
                                    const std::string& key) const = 0;
};

using DatabaseInterfaceRef = std::shared_ptr<IDatabaseInterface>;
} // namespace zeek
