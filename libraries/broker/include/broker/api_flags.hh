#pragma once

namespace broker {

/// Flags that control how to spawn endpoints.
enum class api_flags : int {
  no_flags = 0x00,
  blocking_flag = 0x01,
  nonblocking_flag = 0x02,
};

/// @see api_flags
constexpr api_flags no_api_flags = api_flags::no_flags;

/// @see api_flags
constexpr api_flags blocking = api_flags::blocking_flag;

/// @see api_flags
constexpr api_flags nonblocking = api_flags::nonblocking_flag;

/// @see api_flags
constexpr bool has_api_flags(api_flags haystack, api_flags needle) {
  return (static_cast<int>(haystack) & static_cast<int>(needle)) != 0;
}

} // namespace broker
