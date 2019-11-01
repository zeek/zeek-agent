#pragma once

#include <string>

namespace broker {
namespace version {

/// The type used for version numbers.
using type = unsigned;

constexpr type major = 1;
constexpr type minor = 2;
constexpr type patch = 0;
constexpr auto suffix = "-60";

constexpr type protocol = 2;

/// Determines whether two Broker protocol versions are compatible.
/// @param v The version of the other broker.
/// @returns `true` iff *v* is compatible to this version.
inline bool compatible(type v) {
  return v == protocol;
}

/// Generates a version string of the form `major.minor.patch`.
/// @returns A string representing the Broker version.
std::string string();

} // namespace version
} // namespace broker
