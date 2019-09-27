/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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
