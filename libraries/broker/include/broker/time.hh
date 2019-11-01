#pragma once

#include <chrono>
#include <cstdint>
#include <cstddef>
#include <ratio>
#include <functional>
#include <string>


namespace broker {

/// A fractional timestamp represented in IEEE754 double-precision floating
/// point.
using fractional_seconds = std::chrono::duration<double, std::ratio<1>>;

/// The clock type.
using clock = std::chrono::system_clock;

/// A fractional timestamp with nanosecond precision.
using timespan = std::chrono::duration<int64_t, std::nano>;

/// A point in time anchored at the UNIX epoch: January 1, 1970.
using timestamp = std::chrono::time_point<clock, timespan>;

/// @relates timespan
bool convert(timespan i, fractional_seconds& secs);

/// @relates timespan
bool convert(timespan i, double& secs);

/// @relates timespan
bool convert(timespan i, std::string& str);

/// @relates timestamp
bool convert(timestamp t, std::string& str);

/// @relates timestamp
bool convert(timestamp i, double& secs);

/// @relates timespan
bool convert(double secs, timespan& i);

/// @relates timespan
bool convert(double secs, timestamp& ts);

/// @returns the current point in time (always real/wall clock time).
timestamp now();

/// @relates broker::timespan
inline std::string to_string(const broker::timespan& s) {
  std::string x;
  convert(s, x);
  return x;
}

/// @relates broker::timestamp
inline std::string to_string(const broker::timestamp& t) {
  std::string x;
  convert(t, x);
  return x;
}

/// @relates broker::timestamp
inline broker::timespan to_timespan(double secs) {
  timespan ts;
  convert(secs, ts);
  return ts;
}

/// @relates broker::timestamp
inline broker::timestamp to_timestamp(double secs) {
  timestamp ts;
  convert(secs, ts);
  return ts;
}

} // namespace broker

namespace std {

/// @relates broker::timespan
template <>
struct hash<broker::timespan> {
  size_t operator()(const broker::timespan& s) const {
    return hash<broker::timespan::rep>{}(s.count());
  }
};

/// @relates broker::timestamp
template <>
struct hash<broker::timestamp> {
  size_t operator()(const broker::timestamp& t) const {
    return hash<broker::timespan>{}(t.time_since_epoch());
  }
};

} // namespace std
