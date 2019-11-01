#pragma once

#include <unordered_map>

#include "broker/data.hh"

namespace broker {

/// A snapshot of a data store's contents.
using snapshot = std::unordered_map<data, data>;

} // namespace broker
