#pragma once

#include <functional>
#include <string>

#include <caf/none.hpp>

namespace broker {

/// An empty class with a single instance only.
struct none : caf::none_t {
};

/// @relates none
inline constexpr bool operator==(none, none) noexcept {
  return true;
}

/// @relates none
inline constexpr bool operator!=(none, none) noexcept {
  return false;
}

/// @relates none
inline constexpr bool operator<(none, none) noexcept {
  return false;
}

/// @relates none
inline constexpr bool operator>(none, none) noexcept {
  return false;
}

/// @relates none
inline constexpr bool operator<=(none, none) noexcept {
  return true;
}

/// @relates none
inline constexpr bool operator>=(none, none) noexcept {
  return true;
}

inline bool convert(none, std::string& str) {
  str = "nil";
  return true;
}

/// The only instance of ::none.
/// @relates none
constexpr auto nil = none{};

} // namespace broker

namespace std {

template <>
struct hash<broker::none> {
  using result_type = size_t;

  result_type operator()(broker::none) const {
    return 0;
  }
};

} // namespace std
