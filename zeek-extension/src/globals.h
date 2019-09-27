/**
 *  Copyright (c) 2019-present, The International Computer Science Institute
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "zeekconfiguration.h"

#include <zeek-remote/ibrokermanager.h>
#include <zeek-remote/iquerymanager.h>

namespace zeek {
extern ZeekConfiguration::Ref configuration;
extern IQueryManager::Ref query_manager;
extern IBrokerManager::Ref broker_manager;

osquery::Status initializeGlobals();
} // namespace zeek
