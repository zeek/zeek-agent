#pragma once

#include <chrono>

#include <caf/atom.hpp>
#include <caf/duration.hpp>

namespace broker {
namespace timeout {

using std::chrono::milliseconds;
using std::chrono::seconds;

/// Timeout when peering between two brokers.
constexpr auto peer = seconds(10);

/// Timeout when subscribing to a topic.
constexpr auto subscribe = seconds(5);

/// Timeout for interacting with a data store frontend
constexpr auto frontend = seconds(10);

/// Infinite timeout.
constexpr auto infinite = caf::infinite;

} // namespace timeout
} // namespace broker
